"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'my_geolocate' block
    my_geolocate(container=container)
    # call 'lookup_ip_1' block
    lookup_ip_1(container=container)

    return

@phantom.playbook_block()
def my_geolocate(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("my_geolocate() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # This block retrieves public IP addr info
    ################################################################################

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceAddress","artifact:*.id"])

    parameters = []

    # build parameters list for 'my_geolocate' call
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

    phantom.act("geolocate ip", parameters=parameters, name="my_geolocate", assets=["maxmind"], callback=join_debug_1)

    return


@phantom.playbook_block()
def lookup_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("lookup_ip_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceAddress","artifact:*.id"])

    parameters = []

    # build parameters list for 'lookup_ip_1' call
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

    phantom.act("lookup ip", parameters=parameters, name="lookup_ip_1", assets=["google_dns"], callback=join_debug_1)

    return


@phantom.playbook_block()
def join_debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("join_debug_1() called")

    if phantom.completed(action_names=["my_geolocate", "lookup_ip_1"]):
        # call connected block "debug_1"
        debug_1(container=container, handle=handle)

    return


@phantom.playbook_block()
def debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_1() called")

    name_value = container.get("name", None)
    label_value = container.get("label", None)
    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceAddress","artifact:*.id"])
    my_geolocate_result_data = phantom.collect2(container=container, datapath=["my_geolocate:action_result.data.*.country_name","my_geolocate:action_result.data.*.state_name","my_geolocate:action_result.parameter.context.artifact_id"], action_results=results)
    lookup_ip_1_result_data = phantom.collect2(container=container, datapath=["lookup_ip_1:action_result.summary.hostname","lookup_ip_1:action_result.parameter.context.artifact_id"], action_results=results)

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]
    my_geolocate_result_item_0 = [item[0] for item in my_geolocate_result_data]
    my_geolocate_result_item_1 = [item[1] for item in my_geolocate_result_data]
    lookup_ip_1_summary_hostname = [item[0] for item in lookup_ip_1_result_data]

    parameters = []

    parameters.append({
        "input_1": name_value,
        "input_2": label_value,
        "input_3": container_artifact_cef_item_0,
        "input_4": my_geolocate_result_item_0,
        "input_5": my_geolocate_result_item_1,
        "input_6": lookup_ip_1_summary_hostname,
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

    phantom.custom_function(custom_function="community/debug", parameters=parameters, name="debug_1")

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################
    phantom.debug("chris was here")
    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return