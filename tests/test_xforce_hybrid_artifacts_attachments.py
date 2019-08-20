# -*- coding: utf-8 -*-
"""Tests using pytest_resilient_circuits"""

from __future__ import print_function
import pytest
from resilient_circuits.util import get_config_data, get_function_definition
from resilient_circuits import SubmitTestFunction, FunctionResult

PACKAGE_NAME = "fn_xforce_hybrid"
FUNCTION_NAME = "xforce_hybrid_artifacts_attachments"

# Read the default configuration-data section from the package
config_data = get_config_data(PACKAGE_NAME)

# Provide a simulation of the Resilient REST API (uncomment to connect to a real appliance)
resilient_mock = "pytest_resilient_circuits.BasicResilientMock"


def call_xforce_hybrid_artifacts_attachments_function(circuits, function_params, timeout=10):
    # Fire a message to the function
    evt = SubmitTestFunction("xforce_hybrid_artifacts_attachments", function_params)
    circuits.manager.fire(evt)
    event = circuits.watcher.wait("xforce_hybrid_artifacts_attachments_result", parent=evt, timeout=timeout)
    assert event
    assert isinstance(event.kwargs["result"], FunctionResult)
    pytest.wait_for(event, "complete", True)
    return event.kwargs["result"].value


class TestXforceHybridArtifactsAttachments:
    """ Tests for the xforce_hybrid_artifacts_attachments function"""

    def test_function_definition(self):
        """ Test that the package provides customization_data that defines the function """
        func = get_function_definition(PACKAGE_NAME, FUNCTION_NAME)
        assert func is not None

    @pytest.mark.parametrize("attachment_name, target_ip, incident_id, attachment_id, artifact_id, expected_results", [
        ("text", "text", 123, 123, 123, {"value": "xyz"}),
        ("text", "text", 123, 123, 123, {"value": "xyz"})
    ])
    def test_success(self, circuits_app, attachment_name, target_ip, incident_id, attachment_id, artifact_id, expected_results):
        """ Test calling with sample values for the parameters """
        function_params = { 
            "attachment_name": attachment_name,
            "target_ip": target_ip,
            "incident_id": incident_id,
            "attachment_id": attachment_id,
            "artifact_id": artifact_id
        }
        results = call_xforce_hybrid_artifacts_attachments_function(circuits_app, function_params)
        assert(expected_results == results)