"""
Sets the cn CEF field to country. Normally this might be set by a ip lookup action.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'add_country_code' block
    add_country_code(container=container)

    return

def add_country_code(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('add_country_code() called')

    # collect data for 'add_country_code' call

    parameters = []
    
    # build parameters list for 'add_country_code' call
    parameters.append({
        'container_id': "",
        'name': "Country",
        'contains': "",
        'source_data_identifier': "chris",
        'label': "timera_country",
        'cef_value': "NK",
        'cef_name': "deviceCustomString1",
        'cef_dictionary': "",
    })

    phantom.act("add artifact", parameters=parameters, assets=['phantom container assorted cruds'], callback=retrieve_countries_list, name="add_country_code")

    return

def retrieve_countries_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('retrieve_countries_list() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["custom_list:Bad Nation States", "!=", ""],
        ],
        name="retrieve_countries_list:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_1() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "add_country_code:artifact:*.cef.deviceCustomString1",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all detals of actions 
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return