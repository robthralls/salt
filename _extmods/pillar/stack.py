# -*- coding: utf-8 -*-

# Import Python libs
from __future__ import absolute_import
import os
import posixpath
import logging
from functools import partial
from glob import glob

# Import Salt libs
import salt.ext.six as six
import salt.utils.data
from salt.template import compile_template


log = logging.getLogger(__name__)
strategies = ('overwrite', 'merge-first', 'merge-last', 'remove')


def ext_pillar(minion_id, pillar, *args, **kwargs):
    stack = pillar
    stack_config_files = list(args)
    traverse = {
        'pillar': partial(salt.utils.data.traverse_dict_and_list, pillar),
        'grains': partial(salt.utils.data.traverse_dict_and_list, __grains__),
        'opts': partial(salt.utils.data.traverse_dict_and_list, __opts__),
    }
    for matcher, matchs in six.iteritems(kwargs):
        t, matcher = matcher.split(':', 1)
        if t not in traverse:
            raise Exception(
                'Unknown traverse option "{0}", '
                'should be one of {1}'.format(t, traverse.keys())
            )
        cfgs = matchs.get(traverse[t](matcher, None), [])
        if not isinstance(cfgs, list):
            cfgs = [cfgs]
        stack_config_files += cfgs
    for cfg in stack_config_files:
        if not os.path.isfile(cfg):
            log.warning(
                'Ignoring pillar stack cfg "{0}": '
                'file does not exist'.format(cfg)
            )
            continue
        stack = _process_stack_cfg(cfg, stack, minion_id, pillar)
    return stack


def _process_stack_cfg(cfg, stack, minion_id, pillar):
    basedir = os.path.dirname(cfg)
    items = compile_template(
        cfg,
        salt.loader.render(__opts__, __salt__),
        __opts__['renderer'],
        __opts__['renderer_blacklist'],
        __opts__['renderer_whitelist'],
        __opts__['pillarenv'],
        minion_id=minion_id,
        stack=stack,
    )
    try:
        _ = iter(items['stack'])
    except:
        return stack
    for item in items['stack']:
        if not item.strip():
            continue  # silently ignore whitespace or empty lines
        paths = glob(os.path.join(basedir, item))
        if not paths:
            log.debug(
                'Ignoring pillar stack template "{0}": can\'t find from '
                'root dir "{1}"'.format(item, basedir)
            )
            continue
        for sls in sorted(paths):
            log.debug('Compiling SLS: "{0}"'.format(sls))
            obj = compile_template(
                sls,
                salt.loader.render(__opts__, __salt__),
                __opts__['renderer'],
                __opts__['renderer_blacklist'],
                __opts__['renderer_whitelist'],
                __opts__['pillarenv'],
                minion_id=minion_id,
                stack=stack,
            )
            if obj:
                stack = _merge_dict(stack, obj)
    return stack


def _cleanup(obj):
    if obj:
        if isinstance(obj, dict):
            obj.pop('__', None)
            for k, v in six.iteritems(obj):
                obj[k] = _cleanup(v)
        elif isinstance(obj, list):
            if isinstance(obj[0], dict):
                if '__' in obj[0]:
                    del obj[0]
    return obj


def _merge_dict(stack, obj):
    strategy = obj.pop('__', 'merge-last')
    if strategy not in strategies:
        raise Exception(
            'Unknown strategy "{0}", should be one of {1}'.format(
                strategy,
                strategies
            )
        )
    if strategy == 'overwrite':
        return _cleanup(obj)
    else:
        for k, v in six.iteritems(obj):
            if strategy == 'remove':
                stack.pop(k, None)
                continue
            if k in stack:
                if strategy == 'merge-first':
                    # merge-first is same as merge-last but the other way round
                    # so let's switch stack[k] and v
                    stack_k = stack[k]
                    stack[k] = _cleanup(v)
                    v = stack_k
                if type(stack[k]) != type(v):
                    log.debug('Force overwrite, types differ: '
                              '\'{0}\' != \'{1}\''.format(stack[k], v))
                    stack[k] = _cleanup(v)
                elif isinstance(v, dict):
                    stack[k] = _merge_dict(stack[k], v)
                elif isinstance(v, list):
                    stack[k] = _merge_list(stack[k], v)
                else:
                    stack[k] = v
            else:
                stack[k] = _cleanup(v)
        return stack


def _merge_list(stack, obj):
    strategy = 'merge-last'
    if obj and isinstance(obj[0], dict) and '__' in obj[0]:
        strategy = obj[0]['__']
        del obj[0]
    if strategy not in strategies:
        raise Exception(
            'Unknown strategy "{0}", should be one of {1}'.format(
                strategy,
                strategies
            )
        )
    if strategy == 'overwrite':
        return obj
    elif strategy == 'remove':
        return [item for item in stack if item not in obj]
    elif strategy == 'merge-first':
        return obj + stack
    else:
        return stack + obj
