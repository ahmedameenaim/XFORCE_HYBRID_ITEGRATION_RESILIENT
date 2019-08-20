# -*- coding: utf-8 -*-

"""Generate a default configuration-file section for fn_xforce_hybrid"""

from __future__ import print_function


def config_section_data():
    """Produce the default configuration section for app.config,
       when called by `resilient-circuits config [-c|-u]`
    """
    config_data = u"""[fn_xforce_hybrid]
xforce_api=<enter xforce url api>
xforce_api_key = <enter xforce api key>
xforce_api_password=<enter xforce api password>
xforce_malware_endpoint = <malware endpoint>
xforce_ipReputation_endpoint = <ip endpoint>
hybrid_api = <hybrid url api>
hybrid_scan_endpoint = <scan file endpoint>
hybrid_api_key = <enter hybrid api key>
"""
    return config_data