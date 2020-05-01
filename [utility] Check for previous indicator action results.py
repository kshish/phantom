"""
This playbook checks indicator action run as a cache for the existence of a previously ran indicator and returns the result data if ran before.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'check_for_ioc' block
    check_for_ioc(container=container)

    return

"""
This checks for a cached ioc exists in the artifacts list
"""
def check_for_ioc(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('check_for_ioc() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.requestURL", "!=", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        parameter_format(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2
    missing_url_comment(action=action, success=success, container=container, results=results, handle=handle)

    return

def get_url_action_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('get_url_action_results() called')

    # collect data for 'get_url_action_results' call
    formatted_data_1 = phantom.get_format_data(name='parameter_format__as_list')

    parameters = []
    
    # build parameters list for 'get_url_action_results' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'time_limit': 24,
            'parameters': formatted_part_1,
            'app': "",
            'action_name': "url reputation",
            'max_results': "1",
            'asset': "",
        })

    phantom.act("get action result", parameters=parameters, assets=['phantom'], callback=check_action_results, name="get_url_action_results")

    return

"""
Checks to see if value is return
"""
def check_action_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('check_action_results() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["get_url_action_results:action_result.data.*.action_run", "!=", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        found_filter(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2
    none_found(action=action, success=success, container=container, results=results, handle=handle)

    return

def parameter_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('parameter_format() called')
    
    template = """%%
{{\"url\":\"{0}\"}}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.requestURL",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="parameter_format")

    get_url_action_results(container=container)

    return

def missing_url_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('missing_url_comment() called')

    phantom.comment(container=container, comment="Missing url to check")

    return

def found_in_cache(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('found_in_cache() called')

    formatted_data_1 = phantom.get_format_data(name='found_format')

    phantom.comment(container=container, comment=formatted_data_1)

    return

def missing_cache(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('missing_cache() called')

    formatted_data_1 = phantom.get_format_data(name='missing_format')

    phantom.comment(container=container, comment=formatted_data_1)

    return

def found_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('found_format() called')
    
    template = """%%
Requested: {0} - {1}
Message from past action result:
{2} - {3}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:found_filter:condition_1:get_url_action_results:action_result.parameter.parameters",
        "filtered-data:found_filter:condition_1:get_url_action_results:action_result.message",
        "filtered-data:found_filter:condition_1:get_url_action_results:action_result.data.*.app_name",
        "filtered-data:found_filter:condition_1:get_url_action_results:action_result.data.*.result_data.*.message",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="found_format")

    found_in_cache(container=container)

    return

def found_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('found_filter() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["get_url_action_results:action_result.data.*.action_run", "!=", ""],
        ],
        name="found_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        found_format(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["get_url_action_results:action_result.data.*.action_run", "==", ""],
        ],
        name="found_filter:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        missing_format(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

"""
Added drop_none=True to custom parameters call for phantom.format()
"""
def missing_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('missing_format() called')
    
    template = """No action results found for following parameters: 
{0}"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:found_filter:condition_2:get_url_action_results:action_result.parameter.parameters",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="missing_format")

    missing_cache(container=container)

    return

def none_found(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('none_found() called')
    
    template = """No action results found for following parameters: 
{0}"""

    # parameter list for template variable replacement
    parameters = [
        "get_url_action_results:action_result.parameter.parameters",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="none_found")

    no_actions_found(container=container)

    return

def no_actions_found(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('no_actions_found() called')

    formatted_data_1 = phantom.get_format_data(name='none_found')

    phantom.comment(container=container, comment=formatted_data_1)

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