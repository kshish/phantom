"""
This ends being comments in the code
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'my_geolocate_blagh' block
    my_geolocate_blagh(container=container)

    return

@phantom.playbook_block()
def my_geolocate_blagh(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("my_geolocate_blagh() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceAddress","artifact:*.id"])

    parameters = []

    # build parameters list for 'my_geolocate_blagh' call
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

    phantom.act("geolocate ip", parameters=parameters, name="my_geolocate_blagh", assets=["maxmind"], callback=debug_1)

    return


@phantom.playbook_block()
def debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_1() called")

    name_value = container.get("name", None)
    label_value = container.get("label", None)
    geolocate_ip_1_result_data = phantom.collect2(container=container, datapath=["geolocate_ip_1:action_result.parameter.ip","geolocate_ip_1:action_result.data.*.country_name","geolocate_ip_1:action_result.data.*.country_iso_code","geolocate_ip_1:action_result.parameter.context.artifact_id"], action_results=results)
    my_geolocate_blagh_result_data = phantom.collect2(container=container, datapath=["my_geolocate_blagh:action_result.data.*.country_name","my_geolocate_blagh:action_result.parameter.context.artifact_id"], action_results=results)

    geolocate_ip_1_parameter_ip = [item[0] for item in geolocate_ip_1_result_data]
    geolocate_ip_1_result_item_1 = [item[1] for item in geolocate_ip_1_result_data]
    geolocate_ip_1_result_item_2 = [item[2] for item in geolocate_ip_1_result_data]
    my_geolocate_blagh_result_item_0 = [item[0] for item in my_geolocate_blagh_result_data]

    parameters = []

    parameters.append({
        "input_1": ["Chris was here"],
        "input_2": geolocate_ip_1_parameter_ip,
        "input_3": geolocate_ip_1_result_item_1,
        "input_4": geolocate_ip_1_result_item_2,
        "input_5": name_value,
        "input_6": label_value,
        "input_7": my_geolocate_blagh_result_item_0,
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
    phantom.debug("Chris was here at the end block")
    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return