# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
import re
import time
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from importlib import reload

from wazuh.core.exception import WazuhError
from wazuh.core.results import AffectedItemsWazuhResult, WazuhResult
from wazuh.rbac.tests.utils import init_db

test_path = os.path.dirname(os.path.realpath(__file__))
test_data_path = os.path.join(test_path, 'data/')


@pytest.fixture(scope='function')
def db_setup():
    with patch('wazuh.core.common.wazuh_uid'), patch('wazuh.core.common.wazuh_gid'):
        with patch('sqlalchemy.create_engine', return_value=create_engine("sqlite://")):
            with patch('shutil.chown'), patch('os.chmod'):
                with patch('api.constants.SECURITY_PATH', new=test_data_path):
                    import wazuh.rbac.decorators as decorator

    init_db('schema_security_test.sql', test_data_path)
    reload(decorator)

    yield decorator


permissions = list()
results = list()
with open(test_data_path + 'RBAC_decorators_permissions_white.json') as f:
    configurations_white = [(config['decorator_params'],
                             config['function_params'],
                             config['rbac'],
                             config['fake_system_resources'],
                             config['allowed_resources'],
                             config.get('result', None),
                             'white') for config in json.load(f)]
with open(test_data_path + 'RBAC_decorators_permissions_black.json') as f:
    configurations_black = [(config['decorator_params'],
                             config['function_params'],
                             config['rbac'],
                             config['fake_system_resources'],
                             config['allowed_resources'],
                             config.get('result', None),
                             'black') for config in json.load(f)]

with open(test_data_path + 'RBAC_decorators_resourceless_white.json') as f:
    configurations_resourceless_white = [(config['decorator_params'],
                                          config['rbac'],
                                          config['allowed'],
                                          'white') for config in json.load(f)]
with open(test_data_path + 'RBAC_decorators_resourceless_black.json') as f:
    configurations_resourceless_black = [(config['decorator_params'],
                                          config['rbac'],
                                          config['allowed'],
                                          'black') for config in json.load(f)]


def get_identifier(resources):
    list_params = list()
    for resource in resources:
        resource = resource.split('&')
        for r in resource:
            try:
                list_params.append(re.search(r'^([a-z*]+:[a-z*]+:)(\*|{(\w+)})$', r).group(3))
            except AttributeError:
                pass

    return list_params


@pytest.mark.parametrize('decorator_params, function_params, rbac, '
                         'fake_system_resources, allowed_resources, result, mode',
                         configurations_black + configurations_white)
def test_expose_resources(db_setup, decorator_params, function_params, rbac, fake_system_resources, allowed_resources,
                          result, mode):
    rbac['rbac_mode'] = mode
    db_setup.rbac.set(rbac)

    def mock_expand_resource(resource):
        fake_values = fake_system_resources.get(resource, resource.split(':')[-1])
        return {fake_values} if isinstance(fake_values, str) else set(fake_values)

    with patch('wazuh.rbac.decorators._expand_resource', side_effect=mock_expand_resource):
        @db_setup.expose_resources(**decorator_params)
        def framework_dummy(**kwargs):
            for target_param, allowed_resource in zip(get_identifier(decorator_params['resources']), allowed_resources):
                assert set(kwargs[target_param]) == set(allowed_resource)
                assert 'call_func' not in kwargs
                return True

        try:
            output = framework_dummy(**function_params)
            assert (result is None or result == "allow")
            assert output == function_params.get('call_func', True) or isinstance(output, AffectedItemsWazuhResult)
        except WazuhError as e:
            assert (result is None or result == "deny")
            for allowed_resource in allowed_resources:
                assert (len(allowed_resource) == 0)
            assert (e.code == 4000)


@pytest.mark.parametrize('decorator_params, rbac, allowed, mode',
                         configurations_resourceless_white + configurations_resourceless_black)
def test_expose_resourcesless(db_setup, decorator_params, rbac, allowed, mode):
    rbac['rbac_mode'] = mode
    db_setup.rbac.set(rbac)

    def mock_expand_resource(resource):
        return {'*'}

    with patch('wazuh.rbac.decorators._expand_resource', side_effect=mock_expand_resource):
        @db_setup.expose_resources(**decorator_params)
        def framework_dummy():
            pass

        try:
            framework_dummy()
            assert allowed
        except WazuhError as e:
            assert (not allowed)
            assert (e.code == 4000)


def _conf_payload():
    return {
        "auth": {
            "use_password": "yes",
            "ssl_manager_key": "etc/sslmanager.key",
            "key_request": {"enabled": "no"}
        },
        "integration": {
            "secret": "topsecret",
            "token": "abcd-1234"
        },
        "authd.pass": "P4ssW0rd!"
    }


def _conf_result_payload():
    r = AffectedItemsWazuhResult(all_msg="ok", some_msg="ok", none_msg="ok")
    r.affected_items.append({
        "auth": {"use_password": "no", "ssl_manager_key": "etc/sslmanager.key"},
        "integration": {"secret": "topsecret"},
        "authd.pass": "P4ssW0rd!"
    })
    r.total_affected_items = 1
    return r


def test_mask_sensitive_config_without_permissions(db_setup):
    db_setup.rbac.set({'rbac_mode': 'white'})

    @db_setup.mask_sensitive_config()
    def get_conf():
        return _conf_payload()

    result = get_conf()
    assert result["authd.pass"] == "*****"
    assert result["integration"]["secret"] == "topsecret"


@pytest.mark.parametrize('wrap', [False, True])
def test_mask_sensitive_config_haproxy_helper_passwords(db_setup, wrap):
    """HAProxy helper passwords are masked with and without the "cluster" wrapper."""
    db_setup.rbac.set({'rbac_mode': 'white'})
    helper = {"haproxy_password": "HAPROXYSECRET", "client_cert_password": "CERTSECRET", "port": 5555}

    @db_setup.mask_sensitive_config()
    def get_conf():
        return {"cluster": {"haproxy_helper": helper}} if wrap else {"haproxy_helper": helper}

    result = get_conf()
    result = result["cluster"]["haproxy_helper"] if wrap else result["haproxy_helper"]
    assert result["haproxy_password"] == "*****"
    assert result["client_cert_password"] == "*****"
    assert result["port"] == 5555


def test_mask_sensitive_config_raw_xml_haproxy_helper_password_with_escaped_lt(db_setup):
    """A backslash-escaped '<' is part of the value, so the whole password is masked."""
    db_setup.rbac.set({'rbac_mode': 'white'})
    xml = (
        "<ossec_config><cluster><haproxy_helper><haproxy_password>Xy7\\<%kLTAIL</haproxy_password>"
        "</haproxy_helper></cluster></ossec_config>"
    )

    @db_setup.mask_sensitive_config()
    def get_conf_raw():
        return xml

    result = get_conf_raw()
    assert "Xy7" not in result and "TAIL" not in result
    assert "<haproxy_password>*****</haproxy_password>" in result


def test_mask_sensitive_config_raw_xml_haproxy_helper_passwords(db_setup):
    """HAProxy helper passwords are masked in raw XML for unprivileged users."""
    db_setup.rbac.set({'rbac_mode': 'white'})
    xml = (
        "<ossec_config><cluster><haproxy_helper><haproxy_password>HAPROXYSECRET</haproxy_password>"
        "<client_cert_password>CERTSECRET</client_cert_password></haproxy_helper></cluster></ossec_config>"
    )

    @db_setup.mask_sensitive_config()
    def get_conf_raw():
        return xml

    result = get_conf_raw()
    assert "HAPROXYSECRET" not in result and "CERTSECRET" not in result
    assert "<haproxy_password>*****</haproxy_password>" in result


def test_mask_sensitive_config_with_permissions(db_setup):
    db_setup.rbac.set({'rbac_mode': 'white', 'manager:update_config': {'*:*': 'allow'}})

    @db_setup.mask_sensitive_config()
    def get_conf():
        return _conf_payload()

    result = get_conf()
    assert result["authd.pass"] == "P4ssW0rd!"


def test_mask_sensitive_config_on_affected_items_result(db_setup):
    db_setup.rbac.set({'rbac_mode': 'white'})

    @db_setup.mask_sensitive_config()
    def get_conf_result():
        return _conf_result_payload()

    res = get_conf_result()
    item = res.affected_items[0]
    assert item["authd.pass"] == "*****"
    assert item["integration"]["secret"] == "topsecret"


def _agent_conf_wazuh_result_payload():
    """Shape returned by `get_agent_config`: the active configuration under 'data'."""
    return WazuhResult({'data': {
        "name": "wazuh",
        "node_name": "node01",
        "node_type": "master",
        "key": "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH",
        "port": 1516,
        "authd.pass": "P4ssW0rd!"
    }})


def _labels_wazuh_result_payload():
    """Shape returned by `get_agent_config` for the agent/labels pair, where 'key' is a label name."""
    return WazuhResult({'data': {
        "labels": [{"value": "north", "key": "site"}, {"value": "prod", "key": "env"}]
    }})


def test_mask_sensitive_config_on_wazuh_result(db_setup):
    """Sensitive values under 'data' are masked; a WazuhResult is a MutableMapping, not a dict."""
    db_setup.rbac.set({'rbac_mode': 'white'})

    @db_setup.mask_sensitive_config()
    def get_conf_result():
        return _agent_conf_wazuh_result_payload()

    res = get_conf_result()
    assert res['data']["key"] == "*****"
    assert res['data']["authd.pass"] == "*****"
    assert res['data']["node_name"] == "node01"


def test_mask_sensitive_config_on_wazuh_result_with_permissions(db_setup):
    db_setup.rbac.set({'rbac_mode': 'white', 'manager:update_config': {'*:*': 'allow'}})

    @db_setup.mask_sensitive_config()
    def get_conf_result():
        return _agent_conf_wazuh_result_payload()

    res = get_conf_result()
    assert res['data']["key"] == "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH"


def test_mask_sensitive_config_keeps_label_names(db_setup):
    """Label names are members called 'key' that carry no secret and must survive masking."""
    db_setup.rbac.set({'rbac_mode': 'white'})

    @db_setup.mask_sensitive_config()
    def get_conf_result():
        return _labels_wazuh_result_payload()

    res = get_conf_result()
    assert [label["key"] for label in res['data']["labels"]] == ["site", "env"]


# ---------------------------------------------------------------------------
# Tests for _has_update_permissions (the RBAC gate for masking)
# ---------------------------------------------------------------------------

def test_has_update_permissions_no_perms(db_setup):
    """Returns False when RBAC context holds no relevant action."""
    db_setup.rbac.set({'rbac_mode': 'white'})
    assert db_setup._has_update_permissions() is False


def test_has_update_permissions_with_manager_update_config(db_setup):
    """Returns True when manager:update_config is granted."""
    db_setup.rbac.set({'rbac_mode': 'white', 'manager:update_config': {'*:*': 'allow'}})
    assert db_setup._has_update_permissions() is True


def test_has_update_permissions_with_cluster_update_config(db_setup):
    """Returns True when cluster:update_config is granted."""
    db_setup.rbac.set({'rbac_mode': 'white', 'cluster:update_config': {'node:id:master-node': 'allow'}})
    assert db_setup._has_update_permissions() is True


def test_has_update_permissions_read_only_role(db_setup):
    """Returns False for a user that only holds :read — the readonly-role CVE attack vector."""
    db_setup.rbac.set({'rbac_mode': 'white', 'manager:read': {'*:*': 'allow'}})
    assert db_setup._has_update_permissions() is False


def test_has_update_permissions_empty_action_dict(db_setup):
    """Returns False when update_config key exists but the resource map is empty."""
    db_setup.rbac.set({'rbac_mode': 'white', 'manager:update_config': {}})
    assert db_setup._has_update_permissions() is False


def test_has_update_permissions_non_dict_action_value(db_setup):
    """Returns False when the action value is not a dict (malformed RBAC token)."""
    db_setup.rbac.set({'rbac_mode': 'white', 'manager:update_config': None})
    assert db_setup._has_update_permissions() is False


def test_has_update_permissions_none_rbac(db_setup):
    """Returns False gracefully when the RBAC context variable returns None."""
    db_setup.rbac.set(None)
    assert db_setup._has_update_permissions() is False


def test_has_update_permissions_deny_manager_update_config(db_setup):
    """Returns False when manager:update_config has effect=deny."""
    db_setup.rbac.set({'rbac_mode': 'white', 'manager:update_config': {'*:*': 'deny'}})
    assert db_setup._has_update_permissions() is False


def test_has_update_permissions_deny_cluster_update_config(db_setup):
    """Returns False when cluster:update_config has effect=deny."""
    db_setup.rbac.set({'rbac_mode': 'white', 'cluster:update_config': {'node:id:master-node': 'deny'}})
    assert db_setup._has_update_permissions() is False


def test_has_update_permissions_mixed_deny_allow_allows(db_setup):
    """Returns True when at least one resource carries allow, even if others carry deny."""
    db_setup.rbac.set({
        'rbac_mode': 'white',
        'manager:update_config': {
            'node:id:worker-1': 'deny',
            'node:id:master': 'allow'
        }
    })
    assert db_setup._has_update_permissions() is True


def test_has_update_permissions_all_deny(db_setup):
    """Returns False when all resources carry deny."""
    db_setup.rbac.set({
        'rbac_mode': 'white',
        'manager:update_config': {
            'node:id:worker-1': 'deny',
            'node:id:worker-2': 'deny'
        }
    })
    assert db_setup._has_update_permissions() is False


def test_mask_sensitive_config_raw_xml_with_deny_rule(db_setup):
    """Verifies that cluster.key is masked when user has manager:update_config deny rule."""
    db_setup.rbac.set({
        'rbac_mode': 'white',
        'manager:read': {'*:*': 'allow'},
        'manager:update_config': {'*:*': 'deny'}
    })

    @db_setup.mask_sensitive_config()
    def get_conf_raw():
        return _XML_WITH_CLUSTER_KEY

    result = get_conf_raw()
    assert "SECRETCLUSTERKEY" not in result
    assert "<key>*****</key>" in result


def test_mask_sensitive_config_raw_xml_with_cluster_deny_rule(db_setup):
    """Verifies that cluster.key is masked when user has cluster:update_config deny rule."""
    db_setup.rbac.set({
        'rbac_mode': 'white',
        'cluster:read': {'*:*': 'allow'},
        'cluster:update_config': {'node:id:master-node': 'deny'}
    })

    @db_setup.mask_sensitive_config()
    def get_conf_raw():
        return _XML_WITH_CLUSTER_KEY

    result = get_conf_raw()
    assert "SECRETCLUSTERKEY" not in result
    assert "<key>*****</key>" in result


# ---------------------------------------------------------------------------
# Tests for raw XML masking ( _mask_payload str branch)
# ---------------------------------------------------------------------------

_XML_WITH_CLUSTER_KEY = """\
<ossec_config>
  <cluster>
    <name>wazuh</name>
    <node_name>master-node</node_name>
    <key>SECRETCLUSTERKEY</key>
    <port>1516</port>
  </cluster>
  <global>
    <key>this_should_not_be_masked</key>
  </global>
</ossec_config>"""

_XML_WITHOUT_CLUSTER_KEY = """\
<ossec_config>
  <cluster>
    <name>wazuh</name>
    <node_name>master-node</node_name>
  </cluster>
</ossec_config>"""

_XML_MULTIPLE_CLUSTER_BLOCKS = """\
<ossec_config>
  <cluster>
    <key>FIRSTKEY</key>
  </cluster>
  <cluster>
    <key>SECONDKEY</key>
  </cluster>
</ossec_config>"""

_XML_MULTILINE_KEY = """\
<ossec_config>
  <cluster>
    <key>
      MULTILINE
      SECRET
    </key>
  </cluster>
</ossec_config>"""


# --- mask_sensitive_config with raw XML payload ---

def test_mask_sensitive_config_raw_xml_without_permissions(db_setup):
    """Raw XML cluster key is masked for unprivileged users."""
    db_setup.rbac.set({'rbac_mode': 'white'})

    @db_setup.mask_sensitive_config()
    def get_conf_raw():
        return _XML_WITH_CLUSTER_KEY

    result = get_conf_raw()
    assert isinstance(result, str)
    assert "SECRETCLUSTERKEY" not in result
    assert "<key>*****</key>" in result
    # Non-cluster <key> must survive
    assert "this_should_not_be_masked" in result


def test_mask_sensitive_config_raw_xml_with_permissions(db_setup):
    """Raw XML is returned unmodified for users with update-config permissions."""
    db_setup.rbac.set({'rbac_mode': 'white', 'manager:update_config': {'*:*': 'allow'}})

    @db_setup.mask_sensitive_config()
    def get_conf_raw():
        return _XML_WITH_CLUSTER_KEY

    result = get_conf_raw()
    assert result == _XML_WITH_CLUSTER_KEY


def test_mask_sensitive_config_raw_xml_cluster_perm(db_setup):
    """cluster:update_config is also accepted as a privileged permission."""
    db_setup.rbac.set({'rbac_mode': 'white', 'cluster:update_config': {'*:*': 'allow'}})

    @db_setup.mask_sensitive_config()
    def get_conf_raw():
        return _XML_WITH_CLUSTER_KEY

    result = get_conf_raw()
    assert result == _XML_WITH_CLUSTER_KEY


def test_mask_sensitive_config_raw_xml_no_cluster_block(db_setup):
    """XML without a <cluster> block is returned unmodified (no masking needed)."""
    db_setup.rbac.set({'rbac_mode': 'white'})

    @db_setup.mask_sensitive_config()
    def get_conf_raw():
        return _XML_WITHOUT_CLUSTER_KEY

    result = get_conf_raw()
    assert result == _XML_WITHOUT_CLUSTER_KEY


def test_mask_sensitive_config_does_not_raise_on_masking_error(db_setup):
    """If masking raises internally the endpoint must still return a result."""
    db_setup.rbac.set({'rbac_mode': 'white'})

    with patch.object(db_setup, '_mask_payload', side_effect=RuntimeError("boom")):
        @db_setup.mask_sensitive_config()
        def get_conf():
            return _conf_payload()

        # Should NOT raise; the decorator catches the error gracefully.
        result = get_conf()
        assert result is not None


# ---------------------------------------------------------------------------
# Tests for whitespace/attribute variants of the masked tags (regression for
# the mask regex missing tags written as <cluster >, <cluster\t> or with
# attributes, which the manager's own XML parser still treats as <cluster>)
# ---------------------------------------------------------------------------

_XML_CLUSTER_TAG_WITH_SPACE = """\
<ossec_config>
  <cluster >
    <key>SECRETCLUSTERKEY</key>
  </cluster>
</ossec_config>"""

_XML_CLUSTER_TAG_WITH_TAB = "<ossec_config>\n  <cluster\t>\n    <key>SECRETCLUSTERKEY</key>\n  </cluster>\n</ossec_config>"

_XML_CLUSTER_TAG_WITH_ATTRIBUTE = """\
<ossec_config>
  <cluster foo="bar">
    <key>SECRETCLUSTERKEY</key>
  </cluster>
</ossec_config>"""

_XML_KEY_TAG_WITH_SPACE = """\
<ossec_config>
  <cluster>
    <key >SECRETCLUSTERKEY</key>
  </cluster>
</ossec_config>"""

_XML_CLUSTER_TAG_WITH_LT_IN_ATTRIBUTE = """\
<ossec_config>
  <cluster note="a < b">
    <key>SECRETCLUSTERKEY</key>
  </cluster>
</ossec_config>"""

_XML_KEY_TAG_WITH_LT_IN_ATTRIBUTE = """\
<ossec_config>
  <cluster>
    <key note="<">SECRETCLUSTERKEY</key>
  </cluster>
</ossec_config>"""

_XML_DECOY_TAG_WITH_CLUSTER_PREFIX = """\
<ossec_config>
  <clusterx>
    <key>NOTSECRET</key>
  </clusterx>
</ossec_config>"""


@pytest.mark.parametrize('xml_payload', [
    _XML_CLUSTER_TAG_WITH_SPACE,
    _XML_CLUSTER_TAG_WITH_TAB,
    _XML_CLUSTER_TAG_WITH_ATTRIBUTE,
    _XML_KEY_TAG_WITH_SPACE,
    _XML_CLUSTER_TAG_WITH_LT_IN_ATTRIBUTE,
    _XML_KEY_TAG_WITH_LT_IN_ATTRIBUTE,
])
def test_mask_sensitive_config_raw_xml_tag_whitespace_variants(db_setup, xml_payload):
    """Whitespace/attributes on the opening tag must not bypass the mask, and the mask must land in place."""
    db_setup.rbac.set({'rbac_mode': 'white'})

    @db_setup.mask_sensitive_config()
    def get_conf_raw():
        return xml_payload

    result = get_conf_raw()
    assert "SECRETCLUSTERKEY" not in result
    assert "<key" in result and "</key" in result
    assert "*****" in result


def test_mask_sensitive_config_raw_xml_decoy_tag_not_masked(db_setup):
    """A different tag sharing the `cluster` prefix must not be matched."""
    db_setup.rbac.set({'rbac_mode': 'white'})

    @db_setup.mask_sensitive_config()
    def get_conf_raw():
        return _XML_DECOY_TAG_WITH_CLUSTER_PREFIX

    result = get_conf_raw()
    assert result == _XML_DECOY_TAG_WITH_CLUSTER_PREFIX


_XML_COMMENTED_KEY_BEFORE_REAL_KEY = """\
<ossec_config>
  <cluster>
    <!-- <key note>OLDKEY</key> -->
    <key>SECRETCLUSTERKEY</key>
  </cluster>
</ossec_config>"""

_XML_DUPLICATE_KEY_TAGS = """\
<ossec_config>
  <cluster>
    <key>OLDKEY</key>
    <key>SECRETCLUSTERKEY</key>
  </cluster>
</ossec_config>"""

_XML_KEY_VALUE_WITH_EMBEDDED_COMMENT = """\
<ossec_config>
  <cluster>
    <key>SECRETCLUSTERKEY<!-- rotate me --></key>
  </cluster>
</ossec_config>"""

_XML_KEY_CLOSING_TAG_WITH_SPACE = """\
<ossec_config>
  <cluster>
    <key>SECRETCLUSTERKEY</key >
  </cluster>
</ossec_config>"""

_XML_COMMENT_WITH_APOSTROPHE_BEFORE_REAL_KEY = """\
<ossec_config>
  <cluster>
    <!-- <key is the cluster's shared secret -->
    <key>SECRETCLUSTERKEY</key>
  </cluster>
  <indexer>
    <ssl>
      <key>/etc/filebeat/certs/filebeat-key.pem<!-- don't move --></key>
    </ssl>
  </indexer>
  <!-- <cluster></cluster> -->
</ossec_config>"""


@pytest.mark.parametrize('xml_payload', [
    _XML_COMMENTED_KEY_BEFORE_REAL_KEY,
    _XML_DUPLICATE_KEY_TAGS,
    _XML_KEY_VALUE_WITH_EMBEDDED_COMMENT,
    _XML_KEY_CLOSING_TAG_WITH_SPACE,
    _XML_COMMENT_WITH_APOSTROPHE_BEFORE_REAL_KEY,
])
def test_mask_sensitive_config_raw_xml_all_key_occurrences_masked(db_setup, xml_payload):
    """A prior <key> (commented-out or duplicated) or a comment inside the value must not leave the real key in clear text."""
    db_setup.rbac.set({'rbac_mode': 'white'})

    @db_setup.mask_sensitive_config()
    def get_conf_raw():
        return xml_payload

    result = get_conf_raw()
    assert "SECRETCLUSTERKEY" not in result
    assert "OLDKEY" not in result


_XML_CLUSTER_NEVER_CLOSES = """\
<ossec_config>
  <cluster>
    <key>SECRETCLUSTERKEY</key>
"""

_XML_CLUSTER_CLOSING_TAG_TYPO = """\
<ossec_config>
  <cluster>
    <key>SECRETCLUSTERKEY</key>
  </clustr>
</ossec_config>"""

_XML_CLUSTER_CLOSE_INSIDE_COMMENT = """\
<ossec_config>
  <cluster>
    <!-- old block: </cluster> -->
    <key>SECRETCLUSTERKEY</key>
  </cluster>
</ossec_config>"""

_XML_CLUSTER_NESTED_IN_NODES = """\
<ossec_config>
  <cluster>
    <nodes><cluster>10.0.0.1</cluster></nodes>
    <key>SECRETCLUSTERKEY</key>
  </cluster>
</ossec_config>"""


@pytest.mark.parametrize('xml_payload', [
    _XML_CLUSTER_NEVER_CLOSES,
    _XML_CLUSTER_CLOSING_TAG_TYPO,
    _XML_CLUSTER_CLOSE_INSIDE_COMMENT,
    _XML_CLUSTER_NESTED_IN_NODES,
])
def test_mask_sensitive_config_raw_xml_missing_or_fake_block_close(db_setup, xml_payload):
    """A missing, misspelled, or commented-out </cluster> must not leave the whole block unmasked."""
    db_setup.rbac.set({'rbac_mode': 'white'})

    @db_setup.mask_sensitive_config()
    def get_conf_raw():
        return xml_payload

    result = get_conf_raw()
    assert "SECRETCLUSTERKEY" not in result


_XML_MIXED_CASE_TAGS = """\
<ossec_config>
  <Cluster>
    <Key>SECRETCLUSTERKEY</Key>
  </Cluster>
</ossec_config>"""


def test_mask_sensitive_config_raw_xml_mixed_case_tags(db_setup):
    """<Cluster>/<Key> must mask too: configuration.py lowercases tags when it reads them back."""
    db_setup.rbac.set({'rbac_mode': 'white'})

    @db_setup.mask_sensitive_config()
    def get_conf_raw():
        return _XML_MIXED_CASE_TAGS

    result = get_conf_raw()
    assert "SECRETCLUSTERKEY" not in result


def test_mask_sensitive_config_raw_xml_unclosed_key_many_comments_is_fast(db_setup):
    """An unclosed <key> followed by many comments must not trigger catastrophic regex backtracking (ReDoS guard)."""
    db_setup.rbac.set({'rbac_mode': 'white'})
    payload = "<ossec_config><cluster><key>" + "<!--c-->" * 40 + "</cluster></ossec_config>"

    @db_setup.mask_sensitive_config()
    def get_conf_raw():
        return payload

    start = time.perf_counter()
    get_conf_raw()
    elapsed = time.perf_counter() - start
    assert elapsed < 2.0


_XML_CLUSTER_CLOSE_INSIDE_OSXML_COMMENT = """\
<ossec_config>
  <cluster>
    <! old block: </cluster> !>
    <key>SECRETCLUSTERKEY</key>
  </cluster>
</ossec_config>"""


def test_mask_sensitive_config_raw_xml_close_inside_osxml_style_comment(db_setup):
    """A </cluster> written inside an os_xml-style <! ... !> comment must not truncate the block early.

    os_xml's own comment reader (_oscomment) closes a comment opened with '<!' at the first
    '-->' or '!>', not only the W3C '-->' form.
    """
    db_setup.rbac.set({'rbac_mode': 'white'})

    @db_setup.mask_sensitive_config()
    def get_conf_raw():
        return _XML_CLUSTER_CLOSE_INSIDE_OSXML_COMMENT

    result = get_conf_raw()
    assert "SECRETCLUSTERKEY" not in result


def test_mask_xml_by_path_three_level_path_missing_middle_tag_is_fast(db_setup):
    """A 3-tag path whose middle tag is absent from the block must not backtrack exponentially over trailing
    comments (ReDoS guard for the cluster.haproxy_helper.* paths)."""
    payload = "<cluster>" + "<!--c-->" * 40

    start = time.perf_counter()
    result = db_setup._mask_xml_by_path(payload, "cluster.haproxy_helper.haproxy_password", "*****")
    elapsed = time.perf_counter() - start

    assert elapsed < 2.0
    assert result == payload
