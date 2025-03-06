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

    return

@phantom.playbook_block()
def my_geolocate(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("my_geolocate() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # This is a comment
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

    phantom.act("geolocate ip", parameters=parameters, name="my_geolocate", assets=["maxmind"], callback=my_geolocate_callback)

    return


@phantom.playbook_block()
def my_geolocate_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("my_geolocate_callback() called")

    
    debug_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    decision_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_1() called")

    name_value = container.get("name", None)
    vita_value = container.get("vita", None)
    my_geolocate_result_data = phantom.collect2(container=container, datapath=["my_geolocate:action_result.data.*.country_name","my_geolocate:action_result.parameter.context.artifact_id"], action_results=results)
    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.rm/f","artifact:*.cef.123","artifact:*.cef.some field with spaces","artifact:*.id"])

    my_geolocate_result_item_0 = [item[0] for item in my_geolocate_result_data]
    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]
    container_artifact_cef_item_1 = [item[1] for item in container_artifact_data]
    container_artifact_cef_item_2 = [item[2] for item in container_artifact_data]

    parameters = []

    parameters.append({
        "input_1": name_value,
        "input_2": vita_value,
        "input_3": my_geolocate_result_item_0,
        "input_4": container_artifact_cef_item_0,
        "input_5": container_artifact_cef_item_1,
        "input_6": container_artifact_cef_item_2,
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
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="or",
        conditions=[
            ["my_geolocate:action_result.data.*.country_name", "==", "United States"],
            ["my_geolocate:action_result.data.*.country_name", "==", "Canada"]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        set_severity_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    set_severity_3(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def set_severity_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("set_severity_2() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_severity(container=container, severity="low")

    container = phantom.get_container(container.get('id', None))

    return


@phantom.playbook_block()
def set_severity_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("set_severity_3() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_severity(container=container, severity="high")

    container = phantom.get_container(container.get('id', None))

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################
    phantom.debug("Chris was Here")
    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return