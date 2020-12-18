"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'cf_community_datetime_modify_1' block
    cf_community_datetime_modify_1(container=container)

    return

def cf_community_datetime_modify_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_community_datetime_modify_1() called')
    
    container_data_0 = phantom.collect2(container=container, datapath=['artifact:*.cef.deviceCustomDate1', 'artifact:*.id'])
    literal_values_0 = [
        [
            "%Y-%m-%d",
            0,
            "%m-%d-%Y",
        ],
    ]

    parameters = []

    for item0 in container_data_0:
        for item1 in literal_values_0:
            parameters.append({
                'input_datetime': item0[0],
                'input_format_string': item1[0],
                'modification_unit': item1[1],
                'amount_to_modify': item1[1],
                'output_format_string': item1[2],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "community/datetime_modify", returns the custom_function_run_id
    phantom.custom_function(custom_function='community/datetime_modify', parameters=parameters, name='cf_community_datetime_modify_1', callback=format_1)

    return

def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_1() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "cf_community_datetime_modify_1:custom_function_result.data.datetime_string",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return