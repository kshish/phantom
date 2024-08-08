"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'my_geo_locate' block
    my_geo_locate(container=container)

    return

@phantom.playbook_block()
def my_geo_locate(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("my_geo_locate() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # this action looks up an ip and returns public ip info
    ################################################################################

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceAddress","artifact:*.id"])

    parameters = []

    # build parameters list for 'my_geo_locate' call
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

    phantom.act("geolocate ip", parameters=parameters, name="my_geo_locate", assets=["maxmind"], callback=debug_1)

    return


@phantom.playbook_block()
def debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_1() called")

    name_value = container.get("name", None)
    label_value = container.get("label", None)
    my_geo_locate_result_data = phantom.collect2(container=container, datapath=["my_geo_locate:action_result.status","my_geo_locate:action_result.message","my_geo_locate:action_result.data.*.country_name","my_geo_locate:action_result.parameter.ip","my_geo_locate:action_result.parameter.context.artifact_id"], action_results=results)
    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceAddress","artifact:*.id"])

    my_geo_locate_result_item_0 = [item[0] for item in my_geo_locate_result_data]
    my_geo_locate_result_message = [item[1] for item in my_geo_locate_result_data]
    my_geo_locate_result_item_2 = [item[2] for item in my_geo_locate_result_data]
    my_geo_locate_parameter_ip = [item[3] for item in my_geo_locate_result_data]
    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]

    parameters = []

    parameters.append({
        "input_1": my_geo_locate_result_item_0,
        "input_2": my_geo_locate_result_message,
        "input_3": my_geo_locate_result_item_2,
        "input_4": container_artifact_cef_item_0,
        "input_5": my_geo_locate_parameter_ip,
        "input_6": name_value,
        "input_7": label_value,
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