"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'locate_source' block
    locate_source(container=container)
    # call 'source_reputation' block
    source_reputation(container=container)
    # call 'virus_search' block
    virus_search(container=container)

    return

def locate_source(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("locate_source() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceAddress","artifact:*.id"])

    parameters = []

    # build parameters list for 'locate_source' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "ip": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("geolocate ip", parameters=parameters, name="locate_source", assets=["maxmind"], callback=join_debug_2)

    return


def source_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("source_reputation() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceDnsDomain","artifact:*.id"])

    parameters = []

    # build parameters list for 'source_reputation' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "domain": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("domain reputation", parameters=parameters, name="source_reputation", assets=["myvt"], callback=join_debug_2)

    return


def virus_search(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("virus_search() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.fileHash","artifact:*.id"])

    parameters = []

    # build parameters list for 'virus_search' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "hash": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("file reputation", parameters=parameters, name="virus_search", assets=["myvt"], callback=join_debug_2)

    return


def join_debug_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_debug_2() called")

    if phantom.completed(action_names=["locate_source", "source_reputation", "virus_search"]):
        # call connected block "debug_2"
        debug_2(container=container, handle=handle)

    return


def debug_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("debug_2() called")

    locate_source_result_data = phantom.collect2(container=container, datapath=["locate_source:action_result.data.*.country_name","locate_source:action_result.parameter.context.artifact_id"], action_results=results)
    virus_search_result_data = phantom.collect2(container=container, datapath=["virus_search:action_result.summary","virus_search:action_result.parameter.context.artifact_id"], action_results=results)
    source_reputation_result_data = phantom.collect2(container=container, datapath=["source_reputation:action_result.summary","source_reputation:action_result.parameter.context.artifact_id"], action_results=results)

    locate_source_result_item_0 = [item[0] for item in locate_source_result_data]
    virus_search_result_item_0 = [item[0] for item in virus_search_result_data]
    source_reputation_result_item_0 = [item[0] for item in source_reputation_result_data]

    parameters = []

    parameters.append({
        "input_1": locate_source_result_item_0,
        "input_2": virus_search_result_item_0,
        "input_3": source_reputation_result_item_0,
        "input_4": None,
        "input_5": None,
        "input_6": None,
        "input_7": None,
        "input_8": None,
        "input_9": None,
        "input_10": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/debug", parameters=parameters, name="debug_2", callback=decision_1)

    return


def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_1() called")



    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    ################################################################################
    ## Custom Code End
    ################################################################################

    return