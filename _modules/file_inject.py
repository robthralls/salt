#!/usr/bin/env python
# -*- coding: utf-8 -*-
r'''
Inject functions into the upstream ``file`` execution module.
'''

# Import python libs
from __future__ import absolute_import
import difflib
import filecmp
import glob
import logging
import os
import re
import shutil

# Import salt libs
import salt.utils.files
import salt.utils.path
import salt.utils.platform
from salt.exceptions import CommandExecutionError, SaltInvocationError

# Import 3rd-party libs
from salt.ext.six.moves import shlex_quote as _cmd_quote

log = logging.getLogger(__name__)

__virtualname__ = 'file'


def __virtual__():
    return __virtualname__


def _add_diff_path(prefix, relpath, ret):
    if 'exclude_files' in ret and ret['exclude_files']:
        for i in ret['exclude_files']:
            if i.startswith('E@'):
                if re.search(i[2:], relpath):
                    return False
            else:
                abspath = os.path.join(prefix, relpath)
                for g in glob.iglob(os.path.join(prefix, i)):
                    if abspath == g or abspath.startswith(g + os.sep):
                        return False
    if 'include_files' in ret and ret['include_files']:
        for i in ret['include_files']:
            if i.startswith('E@'):
                if re.search(i[2:], relpath):
                    return True
            else:
                abspath = os.path.join(prefix, relpath)
                for g in glob.iglob(os.path.join(prefix, i)):
                    if abspath == g or abspath.startswith(g + os.sep):
                        return True
        return False
    return True


def diff_full(l, r, **kwargs):
    r'''
    Return a dictionary of recursive diff results.
    '''
    ret = {
        'l_prefix': '',
        'r_prefix': '',
        'diff': '',
        'diff_q': '',
        'changes': {
            'create': [],
            'replace': [],
            'remove': [],
        },
        'include_files': [],
        'exclude_files': [],
    }
    __is_recursing = False
    if 'recurse' in kwargs:
        ret = kwargs['recurse']
        __is_recursing = True
    if not __is_recursing:
        for i in ['include', 'exclude']:
            if i + '_pat' in kwargs and kwargs[i + '_pat'] is not None:
                ret[i + '_files'].append(kwargs[i + '_pat'])
            if i + '_files' in kwargs and kwargs[i + '_files'] is not None:
                for j in kwargs[i + '_files']:
                    ret[i + '_files'].append(j)
    if os.path.isdir(l) and os.path.isdir(r):
        # compare dictionaries recursively
        if not ret['l_prefix']:
            ret['l_prefix'] = l
        if not ret['r_prefix']:
            ret['r_prefix'] = r
        d = filecmp.dircmp(l, r)
        for i in d.left_only:
            l_relpath = os.path.relpath(os.path.join(l, i), ret['l_prefix'])
            if not _add_diff_path(ret['l_prefix'], l_relpath, ret):
                continue
            ret['changes']['create'].append(l_relpath)
            for out in ('diff', 'diff_q'):
                ret[out] += 'Not in {0}: {1}\n'.format(r, i)
        for i in d.right_only:
            r_relpath = os.path.relpath(os.path.join(r, i), ret['r_prefix'])
            if not _add_diff_path(ret['r_prefix'], r_relpath, ret):
                continue
            ret['changes']['remove'].append(r_relpath)
            for out in ('diff', 'diff_q'):
                ret[out] += 'Only in {0}: {1}\n'.format(r, i)
        for i in sorted(d.funny_files + d.common_funny):
            r_relpath = os.path.relpath(os.path.join(r, i), ret['r_prefix'])
            if not _add_diff_path(ret['r_prefix'], r_relpath, ret):
                continue
            ret['changes']['replace'].append(r_relpath)
            for out in ('diff', 'diff_q'):
                ret[out] += 'Error: Failed to compare: {0}\n'.format(r)
        for i in sorted(d.common_dirs + d.common_files):
            ret = diff_full(
                os.path.join(l, i),
                os.path.join(r, i),
                recurse=ret,
            )
    else:
        if not ret['l_prefix']:
            ret['l_prefix'] = os.path.dirname(l)
        if not ret['r_prefix']:
            ret['r_prefix'] = os.path.dirname(r)
        r_relpath = os.path.relpath(r, ret['r_prefix'])
        if not _add_diff_path(ret['r_prefix'], r_relpath, ret):
            return ret
        if os.path.isfile(l) and os.path.isfile(r):
            if not salt.utils.files.is_text(l) or not salt.utils.files.is_text(r):
                # compare binary files
                if not filecmp.cmp(l, r, shallow=False):
                    ret['changes']['replace'].append(r_relpath)
                    for out in ('diff', 'diff_q'):
                        ret[out] += 'Binary file {0} differs\n'.format(r)
            else:
                # compare text files
                with salt.utils.files.fopen(l, 'r') as l_f:
                    l_lines = l_f.readlines()
                with salt.utils.files.fopen(r, 'r') as r_f:
                    r_lines = r_f.readlines()
                if ''.join(l_lines) != ''.join(r_lines):
                    ret['changes']['replace'].append(r_relpath)
                    ret['diff'] += 'diff {0}\n{1}'.format(
                        r,
                        ''.join(difflib.unified_diff(l_lines, r_lines, l, r)),
                    )
                    ret['diff_q'] += 'File {0} differs\n'.format(r)
        else:
            # file type mismatch
            ret['changes']['replace'].append(r_relpath)
            if os.path.isdir(r):
                msg = (r, 'directory', 'regular file')
            else:
                msg = (r, 'regular file', 'directory')
            for out in('diff', 'diff_q'):
                ret[out] += (
                    'File {0} {1}, expected {2}\n'.format(*msg)
                )
    if not __is_recursing:
        for out in ('diff', 'diff_q'):
            ret[out] = ret[out].strip()
    return ret


def diff(left, right, **kwargs):
    r'''
    Return a recursive unified diff of local files on the minion.
    '''
    left = os.path.expanduser(left)
    right = os.path.expanduser(right)
    ret = ''
    for f in (left, right):
        if not os.path.exists(f):
            ret = 'File {0} does not exist on the minion'.format(f)
            return ret
    res = diff_full(left, right, **kwargs)
    return res['diff']


def diff_q(left, right, **kwargs):
    r'''
    Return a recursive diff of local files, but not file contents.
    '''
    left = os.path.expanduser(left)
    right = os.path.expanduser(right)
    ret = ''
    for f in (left, right):
        if not os.path.exists(f):
            ret = 'File {0} does not exist on the minion'.format(f)
            return ret
    res = diff_full(left, right, **kwargs)
    return res['diff_q']


def _extract(
        cwd,
        sfn,
        archive_format=None,
        archive_compression=None,
        archive_files=None):
    ret = ''
    if archive_format is None:
        ext = sfn.split('.')[-1].lower()
        if ext == 'zip':
            archive_format = 'zip'
        elif ext in ('tar', 'tgz', 'tb2', 'tbz', 'tbz2', 'txz'):
            archive_format = 'tar'
        else:
            ext = sfn.split('.')[-2]
            if ext == 'tar':
                archive_format = 'tar'
    if archive_format not in ('tar', 'zip'):
        raise SaltInvocationError(
            'Invalid archive format \'{0}\'.'.format(archive_format)
        )
    if archive_format == 'zip':
        cmd = 'unzip'
        if not salt.utils.path.which(cmd):
            raise CommandExecutionError(
                '\'{0}\' command not found on minion.'.format(cmd)
            )
        opts = ['{0}']
        if archive_files:
            for f in archive_files:
                opts.append(_cmd_quote(f))
    elif archive_format == 'tar':
        if archive_compression is None:
            ext = sfn.split('.')[-1].lower()
            if ext in ('gz', 'tgz'):
                archive_compression = 'gz'
            elif ext in ('bz2', 'tb2', 'tbz', 'tbz2'):
                archive_compression = 'bz2'
            elif ext in ('xz', 'txz'):
                archive_compression = 'xz'
            elif ext == 'tar':
                archive_compression = None
            else:
                archive_compression = ext
        if archive_compression not in (None, 'gz', 'bz2', 'xz'):
            raise SaltInvocationError(
                'Invalid compression method \'{0}\'.'.format(
                    archive_compression
                )
            )
        if archive_compression == 'gz':
            cmd = 'zcat'
        elif archive_compression == 'bz2':
            cmd = 'bzcat'
        elif archive_compression == 'xz':
            cmd = 'xzcat'
        else:
            cmd = 'cat'
        for i in (cmd, 'tar'):
            if not salt.utils.path.which(i):
                raise CommandExecutionError(
                    '\'{0}\' command not found on minion.'.format(i)
                )
        opts = ['{0} | tar -x -v -f -']
        if __grains__['kernel'] == 'Linux':
            # assume GNU tar
            opts.append('--no-same-owner')
        if archive_files:
            for f in archive_files:
                opts.append(_cmd_quote(f))
    res = __salt__['cmd.run_all'](
        ' '.join((cmd, ' '.join(opts).format(_cmd_quote(sfn)))),
        cwd=cwd,
        python_shell=True,
    )
    if res['retcode'] != 0:
        raise CommandExecutionError(res['stdout'] + res['stderr'])
    ret = res['stdout']
    return ret


def extract(
        name,
        sfn,
        archive_format=None,
        archive_compression=None,
        archive_files=None,
        archive_toplevel=None,
        makedirs=False,
        clean=True,
        include_pat=None,
        exclude_pat=None,
        include_files=None,
        exclude_files=None,
        force=False,
        **kwargs):
    r'''
    Ensure that a cached archive file is extracted to a directory.

    Unlike the upstream :mod:``archive <salt.modules.archive>`` executable
    module, which lists the contents of archives to determine whether or not
    to extract based on missing file names, this implementation performs a
    recursive diff, examining file contents.

    This function uses system commands (``unzip``, ``tar``, etc).

    name
        Directory into which the archive should be extracted.

    sfn
        The location of the cached archive file on the minion.

    archive_format
        One of ``tar`` or ``zip``.

        If omitted, this will be guessed from the ``sfn`` argument.

    archive_compression
        Compression algorithm used with ``tar`` format; one of ``gz``,
        ``bz2``, or ``xz``.

        If omitted, this will be guessed from the ``sfn`` argument.
        Defaults to no compression.

    archive_files
        A list of files to extract from the archive, relative to
        ``archive_toplevel``.

        .. note::
            To ensure consistent behavior (especially with ``unzip``),
            directories should be suffixed with ``/*``.

    archive_toplevel
        The topmost subdirectory to extract, defaulting to all files.

        This is also useful when an archive extracts to a root directory named
        differently than what the archive file name might suggest.

    makedirs : False
        If set to ``True``, then the parent directories will be created to
        facilitate the creation of the named directory. If ``False``, and the
        parent directory of the extracted directory doesn't exist, the state
        will fail.

    clean : True
        If set to ``True``, remove files that exist in ``name``, but were not
        extracted from the ``source`` file.

    include_pat
        Include this pattern in the recursive diff used to determine which
        files to create, change, or remove. Relative to both ``name`` and
        ``archive_toplevel``. May be a file glob or a regex pattern (prepended
        with ``E@``).

        This is appended to the ``include_files`` list of patterns.

    exclude_pat
        Exclude this pattern from the recursive diff used to determine which
        files to create, change, or remove. Relative to both ``name`` and
        ``archive_toplevel``. May be a file glob or a regex pattern (prepended
        with ``E@``).

        This is appended to the ``exclude_files`` list of patterns.

    include_files
        Include this pattern in the recursive diff used to determine which
        files to create, change, or remove. Relative to both ``name`` and
        ``archive_toplevel``. May be a file glob or a regex pattern (prepended
        with ``E@``).

        Default behavior is to include all files.

    exclude_files
        Exclude this pattern from the recursive diff used to determine which
        files to create, change, or remove. Relative to both ``name`` and
        ``archive_toplevel``. May be a file glob or a regex pattern (prepended
        with ``E@``).

    force : False
        Remove ``name`` prior to extraction.
    '''
    ret = {}
    if salt.utils.platform.is_windows():
        raise CommandExecutionError('file.extract does not support Windows')
    if archive_toplevel:
        if archive_files:
            files = archive_files
            archive_files = []
            for f in files:
                archive_files.append(os.path.join(archive_toplevel, f))
        else:
            archive_files = [os.path.join(archive_toplevel, '*')]
    if force:
        if os.path.exists(name):
            log.debug('Removing {0}'.format(name))
            salt.utils.files.rm_rf(name)
    if not os.path.isdir(name) and makedirs:
        log.debug('Making directories for {0}'.format(name))
        __salt__['file.makedirs'](name)
        os.mkdir(name)
    if not os.path.isdir(name):
        raise CommandExecutionError('No such directory \'{0}\'.'.format(name))
    test_dir = sfn + '__test__' + re.sub(r'[:/\\]', '_', name)
    if os.path.exists(test_dir):
        log.debug('Removing {0}'.format(test_dir))
        salt.utils.files.rm_rf(test_dir)
    log.debug('Making directories for {0}'.format(test_dir))
    __salt__['file.makedirs'](test_dir)
    os.mkdir(test_dir)
    _extract(
        test_dir,
        sfn,
        archive_format=archive_format,
        archive_compression=archive_compression,
        archive_files=archive_files,
    )
    if archive_toplevel:
        test_dir = os.path.join(test_dir, archive_toplevel)
    if include_pat is None and include_files is None:
        include_files = set()
        for path in [test_dir, name]:
            for root, dirs, files in os.walk(path):
                for d in dirs:
                    d_relpath = os.path.relpath(os.path.join(root, d), path)
                    include_files.add(d_relpath)
                for f in files:
                    f_relpath = os.path.relpath(os.path.join(root, f), path)
                    include_files.add(f_relpath)
        include_files = list(include_files)
    res = diff_full(
        test_dir,
        name,
        include_pat=include_pat,
        exclude_pat=exclude_pat,
        include_files=include_files,
        exclude_files=exclude_files,
    )
    if res['diff_q']:
        log.debug('Extract test diff:\n' + res['diff_q'])
    else:
        log.debug('No changes.')
    log.debug('res: ' + str(res))
    if __opts__['test']:
        ret = res['diff_q']
        if os.path.exists(test_dir):
            log.debug('Removing {0}'.format(test_dir))
            salt.utils.files.rm_rf(test_dir)
        return ret
    if res['changes']['create']:
        ret['created'] = []
    for relpath in res['changes']['create']:
        src = os.path.join(res['l_prefix'], relpath)
        dst = os.path.join(res['r_prefix'], relpath)
        log.debug('Copying {0} to {1}'.format(src, dst))
        ret['created'].append(relpath)
        if os.path.isdir(src):
            shutil.copytree(src, dst)
        else:
            shutil.copy(src, dst)
    if res['changes']['replace']:
        ret['replaced'] = []
    for relpath in res['changes']['replace']:
        src = os.path.join(res['l_prefix'], relpath)
        dst = os.path.join(res['r_prefix'], relpath)
        dst_dirname = os.path.dirname(dst)
        if not os.path.isdir(dst_dirname):
            log.debug('Making directories for {0}'.format(dst))
            __salt__['file.makedirs'](name)
            os.mkdir(name)
        log.debug('Copying {0} to {1}'.format(src, dst))
        ret['replaced'].append(relpath)
        if os.path.isdir(src):
            shutil.copytree(src, dst)
        else:
            shutil.copy(src, dst)
    if clean:
        if res['changes']['remove']:
            ret['removed'] = []
        for relpath in res['changes']['remove']:
            log.debug('relpath: ' + relpath)
            dst = os.path.join(res['r_prefix'], relpath)
            log.debug('dst: ' + dst)
            if os.path.exists(dst):
                log.debug('Removing {0}'.format(dst))
                ret['removed'].append(relpath)
                salt.utils.files.rm_rf(dst)
    if os.path.exists(test_dir):
        log.debug('Removing {0}'.format(test_dir))
        salt.utils.files.rm_rf(test_dir)
    return ret
