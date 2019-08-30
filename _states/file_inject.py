#!/usr/bin/env python
# -*- coding: utf-8 -*-
r'''
Inject functions into the upstream ``file`` state module.
'''

# Import python libs
from __future__ import absolute_import
import logging
import os
import re

# Import salt libs
import salt.utils.files
import salt.utils.platform
import salt.utils.url
from salt.exceptions import CommandExecutionError

# Import 3rd-party libs
from salt.ext.six.moves.urllib.parse import urlparse as _urlparse

log = logging.getLogger(__name__)

__virtualname__ = 'file'


def __virtual__():
    return __virtualname__


def certificate(
        name,
        pillar_root='tls:certs',
        pillar_cert=None,
        pillar_issuers=None,
        components=None,
        generate=False,
        force=False,
        skip_verify=False,
        skip_dhparam=False,
        key_file=None,
        cert_file=None,
        bits=2048,
        config=None,
        subj=None,
        expire=365,
        renew=30,
        user=None,
        group=None,
        mode=None,
        makedirs=False,
        dir_mode=None,
        show_changes=True,
        **kwargs):
    r'''
    Manage a file containing PEM-encoded cryptographic components, either
    stored in Pillar or generated using OpenSSL system commands.

    name
        The location of the file to manage.

    pillar_root
        A Pillar path, default is ``tls:certs``.

    pillar_cert
        A Pillar path, appended to ``pillar_root``, containing ``components``.

    pillar_issuers
        A list of Pillar paths, appended to ``pillar_root``, containing
        ``cert`` components for use as the ``issuers`` component. Overrides
        the ``issuer`` found in ``pillar_cert``. Issuers are not recursed.

    components
        A list of cryptographic components to include in the file, including:

            ``key``: a PEM-encoded RSA private key
            ``cert``: a PEM-encoded X.509 public key certificate
            ``dh``: a PEM-encoded Diffie-Hellman parameter set

        With ``pillar_cert``, the following are also available:
            ``issuer``: the issuer's PEM-encoded X.509 public key certificate
            ``issuers``: the PEM-encoded X.509 public key certificate chain

        In Pillar, ``issuer`` is the immediate issuing ``pillar_cert`` name,
        which is used to recursively add issuing ``cert`` components.

    generate : False
        If set to ``True``, generate components if they cannot be read from
        ``pillar_cert``, ``key_file``, ``cert_file``, or ``name``.

        .. note::
            Generated certificates are self-signed, so if ``issuers`` is in
            ``components``, it will be silently ignored.

        .. note::
            Generating Diffie-Hellman parameters can take a long time and
            when listed in ``components``, they will always be generated,
            unless a suitable set is found in ``pillar_cert`` or ``name``.
            Setting ``force`` to ``True`` disables this behavior.

    force : False
        If set to ``True``, do not read ``key_file``, ``cert_file``, or
        ``name``, requiring components to come from ``pillar_cert`` or else be
        generated.

    skip_verify : False
        If set to ``True``, components will not be verified. This includes
        checks for bit length, public-private key pair matching, and
        certificate expiration and renewal.

    skip_dhparam : False
        If set to ``True``, skip Diffie-Hellman generation when parameters
        do not already exist in ``name``.

    key_file
        The location of an external private key on the minion.

        .. note::
            External private keys will not be managed, only read.

    cert_file
        The location of an external certificate on the minion.

        .. note::
            External certificates will not be managed, only read.

    bits
        The minimum length of managed private keys and DH parameters, as well
        as the length to generate. Default is ``2048``.

    config
        The location of an OpenSSL configuration file on the minion, useful
        for specifying X.509 extensions in generated certificates.

    subj
        The subject name of generated certificates, using ``/`` to separate
        relative distinguished names, default is ``/CN=localhost``.

    expire
        The number of days until a generated certificate expires. Default is
        ``365``.

    renew
        The number of days before certificate expiration to regenerate both the
        private key and certificate, default is ``30``.

        .. note::
            If ``key_file`` or ``cert_file`` is used, the external files will
            not be updated.

    user
        The user to own the file.

    group
        The group to own the file.

    mode
        The permissions to set on the file.

    makedirs : False
        If set to ``True``, then the parent directories will be created to
        facilitate the creation of the named file. If ``False``, and the parent
        directory of the destination file doesn't exist, the state will fail.

    dir_mode
        If directories are to be created, passing this option specifies the
        permissions for those directories. If this is not set, directories
        will be assigned permissions by adding the execute bit to the mode of
        the files.

    show_changes
        Output a unified diff of the old file and the new file. If ``False``
        return a boolean if any changes were made.
    '''
    ret = {'name': name, 'result': False, 'changes': {}, 'comment': ''}
    kwargs = salt.utils.args.clean_kwargs(**kwargs)  # remove __* keys
    if components is None:
        components = []
    out = {
        'key': None,
        'cert': None,
        'dh': None,
        'issuer': None,
        'issuers': [],
    }
    # get components from pillar
    pcert = {}
    if pillar_cert:
        pcert = __salt__['pillar.get'](
            ':'.join((pillar_root, pillar_cert)),
            {},
        )
    if pcert:
        for c in ('key', 'cert', 'dh'):
            if c in components:
                if c in pcert:
                    out[c] = pcert[c]
                elif c != 'dh' and not generate:
                    ret['comment'] = 'Pillar {0} does not exist'.format(
                        ':'.join((pillar_root, pillar_cert, c)),
                    )
                    return ret
        if 'issuer' in components:
            if 'issuer' in pcert:
                icert = __salt__['pillar.get'](
                    ':'.join((pillar_root, pcert['issuer'])),
                    {},
                )
                if 'cert' in icert:
                    out['issuer'] = icert['cert']
                else:
                    ret['comment'] = 'Pillar {0} does not exist'.format(
                        ':'.join((pillar_root, pcert['issuer'], 'cert')),
                    )
                    return ret
            else:
                ret['comment'] = 'Pillar {0} does not exist'.format(
                    ':'.join((pillar_root, pillar_cert, 'issuer')),
                )
                return ret
        if 'issuers' in components:
            count = 0
            while 'issuer' in pcert and count < 100:
                out['issuers'].append(pcert['issuer'])
                pcert = __salt__['pillar.get'](
                    ':'.join((pillar_root, pcert['issuer'])),
                    {},
                )
                count += 1
    if pillar_issuers:
        out['issuers'] = pillar_issuers
    # read (the first instance of) components from files
    # avoids generating on every state run
    if not force:
        try:
            if not out['key'] and key_file and 'key' not in components:
                res = __salt__['tls.get_pem'](key_file, 'key')
                if res:
                    out['key'] = res[0]
            if not out['cert'] and cert_file and 'cert' not in components:
                res = __salt__['tls.get_pem'](cert_file, 'cert')
                if res:
                    out['cert'] = res[0]
            for c in ('key', 'cert', 'dh'):
                if not out[c] and c in components:
                    res = __salt__['tls.get_pem'](name, c)
                    if res:
                        out[c] = res[0]
        except CommandExecutionError as exc:
            ret['comment'] = exc.strerror
            return ret
    # verify components
    for c in ('key', 'cert', 'dh'):
        if skip_verify or not out[c]:
            continue
        # verify certificate
        if c == 'cert':
            # must have a key defined
            if not out['key']:
                out['cert'] = None
                log.debug('{0}: no key defined'.format(name))
                continue
            # must have a MATCHING key defined
            k_mod = __salt__['tls.get_modulus'](out['key'])
            c_mod = __salt__['tls.get_modulus'](out['cert'])
            if not k_mod or not c_mod or k_mod != c_mod:
                out['cert'] = None
                log.debug('{0}: no matching key defined'.format(name))
                continue
            # renew expiring certificates
            if renew:
                try:
                    renew = int(renew)
                except TypeError:
                    ret['comment'] = '\'{0}\' is not an integer'.format(renew)
                    return ret
                c_exp = __salt__['tls.get_expire_sec'](out['cert'])
                if not c_exp or c_exp < (renew * 86400):
                    if not key_file and 'key' in components:
                        out['key'] = None
                        log.debug('{0}: certificate expired'.format(name))
                    out['cert'] = None
                    continue
        # verify private key and DH parameters
        else:
            # check bit length
            try:
                bits = int(bits)
            except TypeError:
                ret['comment'] = '\'{0}\' is not an integer'.format(bits)
                return ret
            c_bits = __salt__['tls.get_length'](out[c])
            if not c_bits or c_bits < bits:
                out[c] = None
                log.debug('{0}: {1}: component is too short'.format(name, c))
                continue
    if generate:
        if 'key' in components and not out['key']:
            out['key'] = __salt__['tls.generate_key'](bits)
        if 'cert' in components and not out['cert'] and out['key']:
            out['cert'] = __salt__['tls.generate_cert'](
                out['key'],
                config=config,
                subj=subj,
                expire=expire,
            )
            out['issuers'] = []
        if 'dh' in components and not out['dh']:
            if not skip_dhparam:
                out['dh'] = __salt__['tls.generate_dh'](bits)
            else:
                while 'dh' in components:
                    components.remove('dh')
    contents = []
    for c in components:
        if c == 'issuers':
            for i in out['issuers']:
                icert = __salt__['pillar.get'](
                    ':'.join((pillar_root, i)),
                    {},
                )
                if 'cert' not in icert:
                    ret['comment'] = 'Pillar {0} does not exist'.format(
                        ':'.join((pillar_root, i, 'cert')),
                    )
                    return ret
                contents.append(icert['cert'])
        else:
            if c not in out:
                ret['comment'] = 'Unknown component \'{0}\''.format(c)
                return ret
            if not out[c]:
                ret['comment'] = 'No usable \'{0}\' component'.format(c)
                return ret
            contents.append(out[c])
    ret = __states__['file.managed'](
        name=name,
        contents='\n'.join(contents),
        user=user,
        group=group,
        mode=mode,
        makedirs=makedirs,
        dir_mode=dir_mode,
        show_changes=show_changes,
    )
    log.debug('file.managed: {0}'.format(ret))
    return ret


def diff(
        name,
        source,
        include_pat=None,
        exclude_pat=None,
        include_files=None,
        exclude_files=None,
        **kwargs):
    r'''
    Performs a recursive diff on local files, returning results as changes.

    name
        The location of the file or directory to compare.

    source
        The location of the file or directory to compare against.

    include_pat
        Include this pattern. Relative to ``source`` and ``name``.
        May be a file glob or a regex pattern (prepended with ``E@``).

        Appended to the ``include_files`` list of patterns.

    exclude_pat
        Exclude this pattern. Relative to ``source`` and ``name``.
        May be a file glob or a regex pattern (prepended with ``E@``).

        Appended to the ``exclude_files`` list of patterns.

    include_files
        Include this list of files. Relative to ``source`` and ``name``.
        May be a file glob or a regex pattern (prepended with ``E@``).

    exclude_files
        Exclude this list of files. Relative to ``source`` and ``name``.
        May be a file glob or a regex pattern (prepended with ``E@``).

    '''
    ret = {'name': name, 'result': False, 'changes': {}, 'comment': ''}
    kwargs = salt.utils.args.clean_kwargs(**kwargs)  # remove __* keys
    try:
        res = __salt__['file.diff'](
            source,
            name,
            include_pat=include_pat,
            exclude_pat=exclude_pat,
            include_files=include_files,
            exclude_files=exclude_files,
        )
    except CommandExecutionError as exc:
        ret['comment'] = exc.strerror
        return ret
    if res != '':
        ret['changes']['diff'] = res
    ret['result'] = True
    return ret


def extracted(
        name,
        source=None,
        source_hash='',
        skip_verify=False,
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
        user=None,
        group=None,
        mode=None,
        dir_mode=None,
        file_mode=None,
        recurse=None,
        max_depth=None,
        **kwargs):
    r'''
    Ensure that an archive file is extracted to a directory.

    This is an alternative to the upstream :mod:``archive.extracted
    <salt.states.archive.extracted>`` state. Rather than defaulting
    to libtar, this function exclusively uses system commands.

    Instead of extracting directly on top of a directory, the ``source`` file
    is first extracted to a temporary cache directory. When only a subset of
    files are needed, the ``archive_files`` and ``archive_toplevel`` arguments
    can be used to affect the extraction system command.

    A recursive diff is then performed against the cache and ``name`` to
    derive a list of files to manage. Files that do not exist in ``name`` or
    that need to be replaced are copied from cache. If ``clean`` is ``True``,
    files that do not exist in the cache are deleted from ``name``. The
    ``include_pat``, ``include_files``, ``exclude_pat``, and ``exclude_files``
    arguments affect the diff and are applied to both sides.

    name
        Directory into which the archive should be extracted.

    source
        The location of the archive file to be extracted.

    source_hash
        This can be one of the following:
            1. a source hash string
            2. the URI of a file that contains source hash strings

        The function accepts the first encountered long unbroken alphanumeric
        string of correct length as a valid hash, in order from most secure to
        least secure:

        .. code-block:: text

            Type    Length
            ======  ======
            sha512     128
            sha384      96
            sha256      64
            sha224      56
            sha1        40
            md5         32

        See the ``source_hash`` argument description in :mod:`file.managed
        <salt.states.file.managed>` for more details and examples.

    skip_verify : False
        If ``True``, hash verification of remote file sources (``http://``,
        ``https://``, ``ftp://``) will be skipped, and the ``source_hash``
        argument will be ignored.

    archive_format
        One of ``tar`` or ``zip``.

        If omitted, this will be guessed from the ``source`` argument.

    archive_compression
        Compression algorithm used with ``tar`` format; one of ``gz``,
        ``bz2``, or ``xz``.

        If omitted, this will be guessed from the ``source`` argument.
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

        Appended to the ``include_files`` list of patterns.

    exclude_pat
        Exclude this pattern from the recursive diff used to determine which
        files to create, change, or remove. Relative to both ``name`` and
        ``archive_toplevel``. May be a file glob or a regex pattern (prepended
        with ``E@``).

        Appended to the ``exclude_files`` list of patterns.

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
        If set to ``True``, remove ``name`` prior to extraction.

    user
        The user to own the directory. This defaults to the user salt is
        running as on the minion.

    group
        The group ownership set for the directory. This defaults to the group
        salt is running as on the minion.

    dir_mode / mode
        The permissions mode to set on any directories created.

    file_mode
        The permissions mode to set on any files created.

    recurse
        Enforce user/group ownership and mode of directory recursively.

        See the ``recurse`` argument description in :mod:`file.directory
        <salt.states.file.directory>` for more details and examples.

    max_depth
        Limit the ``recurse`` depth. The default is no limit.
    '''
    ret = {'name': name, 'result': False, 'changes': {}, 'comment': ''}
    kwargs = salt.utils.args.clean_kwargs(**kwargs)  # remove __* keys
    if salt.utils.platform.is_windows():
        ret['comment'] = 'file.extracted does not support Windows'
        return ret
    try:
        source_match = __salt__['file.source_list'](
            source,
            source_hash,
            __env__
        )[0]
    except CommandExecutionError as exc:
        ret['comment'] = exc.strerror
        return ret
    urlparsed_source = _urlparse(source_match)
    source_basename = urlparsed_source.path or urlparsed_source.netloc
    source_is_local = urlparsed_source.scheme in ('', 'file')
    if source_is_local:
        # trim "file://" from start of source_match
        source_match = urlparsed_source.path
        if not os.path.isfile(source_match):
            ret['comment'] = (
                'Source file \'{0}\' does not exist'.format(source_match)
            )
            return ret
        cached_source = source_match
    else:
        cached_source = os.path.join(
            __opts__['cachedir'],
            'files',
            __env__,
            re.sub(r'[:/\\]', '_', source_basename),
        )
        if os.path.isdir(cached_source):
            # cache is not a file, so clear it to avoid traceback
            salt.utils.files.rm_rf(cached_source)
        if os.path.exists(cached_source):
            if source_hash:
                try:
                    res = __salt__['file.get_source_sum'](
                        source_hash=source_hash
                    )
                except CommandExecutionError as exc:
                    ret['comment'] = exc.strerror
                    return ret
                hash_type = res['hash_type']
                hsum = res['hsum']
                try:
                    res = __salt__['file.get_sum'](
                        cached_source,
                        form=hash_type
                    )
                except CommandExecutionError as exc:
                    ret['comment'] = exc.strerror
                    return ret
                cached_hsum = res
                if hsum != cached_hsum:
                    salt.utils.files.rm_rf(cached_source)
            else:
                salt.utils.files.rm_rf(cached_source)
    if not os.path.exists(cached_source):
        opts_force = __opts__
        opts_force['test'] = False
        res = __states__['file.managed'](
            cached_source,
            source=source,
            source_hash=source_hash,
            skip_verify=skip_verify,
            makedirs=True,
            __opts__=opts_force,
        )
        log.debug('file.managed: {0}'.format(res))
        if not res['result'] and res['result'] is not None:
            return res
    try:
        res = __salt__['file.extract'](
            name,
            cached_source,
            archive_format=archive_format,
            archive_compression=archive_compression,
            archive_files=archive_files,
            archive_toplevel=archive_toplevel,
            makedirs=makedirs,
            clean=clean,
            include_pat=include_pat,
            exclude_pat=exclude_pat,
            include_files=include_files,
            exclude_files=exclude_files,
            force=force,
        )
    except CommandExecutionError as exc:
        ret['comment'] = exc.strerror
        return ret
    if __opts__['test']:
        ret['result'] = None
        if res:
            ret['comment'] = ['Changes would have been made:', '  diff:']
            for line in res.split('\n'):
                ret['comment'].append(re.sub('^', '    ', line))
            ret['comment'] = '\n'.join(ret['comment'])
            return ret
        else:
            ret['comment'] = ['The extracted archive {0} is in the correct state.'.format(name)]
            return ret
    if res:
        ret['changes']['diff'] = res
    if os.path.isdir(name):
        res = __states__['file.directory'](
            name=name,
            makedirs=makedirs,
            clean=False,
            user=user,
            group=group,
            mode=mode,
            dir_mode=dir_mode,
            file_mode=file_mode,
            recurse=recurse,
            max_depth=max_depth,
        )
        log.debug('file.directory: {0}'.format(res))
        for attr in ('user', 'group', 'mode'):
            if attr in res['changes']:
                ret['changes'][attr] = res['changes'][attr]
    if not res['result']:
        ret['comment'] = res['comment']
        return ret
    ret['result'] = True
    ret['comment'] = 'Archive has been extracted to {0}'.format(name)
    return ret


def mod_watch(name, **kwargs):
    r'''
    Execute a file function based on a watch call.
    '''
    if kwargs['sfun'] == 'extracted':
        kwargs['force'] = True
        return extracted(name, **kwargs)


def pillar(
        name,
        pillar_root=None,
        pillar_file=None,
        allow_functions=None,
        deny_functions=None,
        allow_args=None,
        deny_args=None,
        **kwargs):
    r'''
    Define a file in Pillar.

    name
        The location of the file to manage.

    pillar_root
        A Pillar path, prepended to ``pillar_file``.

    pillar_file
        The Pillar dictionary containing file state module arguments.

        The file state module function defaults to ``managed`` and may be set
        with the ``function`` argument.

    allow_functions
        List of permitted Pillar functions. By default, only ``managed`` and
        ``directory``are permitted.

    deny_functions
        List of forbidden Pillar functions.

    allow_args
        List of permitted Pillar arguments.

    deny_args
        List of forbidden Pillar arguments. ``name`` is always forbidden.
    '''
    if pillar_file not in ['.', '/']:
        name = os.path.join(name, pillar_file)
    ret = {'name': name, 'result': False, 'changes': {}, 'comment': ''}
    kwargs = salt.utils.args.clean_kwargs(**kwargs)  # remove __* keys
    if '..' in os.path.split(name):
        ret['comment'] = 'The name argument contains an illegal path.'
        return ret
    if allow_functions is None:
        allow_functions = ['managed', 'directory']
    p = []
    for pkey in (pillar_root, pillar_file):
        if pkey:
            p.append(pkey)
    if p:
        pargs = __salt__['pillar.get'](':'.join(p), {})
    if not pargs:
        ret['comment'] = 'Pillar {0} does not exist'.format(pillar_file)
        return ret
    if 'name' in pargs:
        ret['comment'] = 'The name argument is forbidden.'
        return ret
    fun = 'file.managed'
    if 'function' in pargs:
        if deny_functions and pargs['function'] in deny_functions:
            ret['comment'] = (
                'The {0} function has been forbidden.'.format(
                    pargs['function']
                )
            )
            return ret
        if pargs['function'] not in allow_functions:
            ret['comment'] = (
                'The {0} function has not been permitted.'.format(
                    pargs['function']
                )
            )
            return ret
        fun = 'file.{0}'.format(pargs['function'])
        del pargs['function']
    if deny_args:
        for arg in deny_args:
            if arg in pargs:
                ret['comment'] = (
                    'The {0} argument has been forbidden.'.format(arg)
                )
                return ret
    if allow_args:
        for arg in pargs:
            if arg not in allow_args:
                ret['comment'] = (
                    'The {0} argument has not been permitted.'.format(arg)
                )
                return ret
    args = pargs.copy()
    args.update(kwargs)
    ret = __states__[fun](name=name, **args)
    log.debug(fun + ': {0}'.format(ret))
    return ret
