"""
This s a comment.\n\nThis playbook is for blah blah demo blah bla\n\n
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'my_geo_locate_ip' block
    my_geo_locate_ip(container=container)

    return

@phantom.playbook_block()
def my_geo_locate_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("my_geo_locate_ip() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceAddress","artifact:*.id"])

    parameters = []

    # build parameters list for 'my_geo_locate_ip' call
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

    phantom.act("geolocate ip", parameters=parameters, name="my_geo_locate_ip", assets=["maxmind"], callback=my_geo_locate_ip_callback)

    return


@phantom.playbook_block()
def my_geo_locate_ip_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("my_geo_locate_ip_callback() called")

    
    debug_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    decision_3(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_1() called")

    name_value = container.get("name", None)
    label_value = container.get("label", None)
    my_geo_locate_ip_result_data = phantom.collect2(container=container, datapath=["my_geo_locate_ip:action_result.data.*.country_iso_code","my_geo_locate_ip:action_result.data.*.country_name","my_geo_locate_ip:action_result.parameter.ip","my_geo_locate_ip:action_result.parameter.context.artifact_id"], action_results=results)

    my_geo_locate_ip_result_item_0 = [item[0] for item in my_geo_locate_ip_result_data]
    my_geo_locate_ip_result_item_1 = [item[1] for item in my_geo_locate_ip_result_data]
    my_geo_locate_ip_parameter_ip = [item[2] for item in my_geo_locate_ip_result_data]

    parameters = []

    parameters.append({
        "input_1": my_geo_locate_ip_result_item_0,
        "input_2": my_geo_locate_ip_result_item_1,
        "input_3": name_value,
        "input_4": label_value,
        "input_5": my_geo_locate_ip_parameter_ip,
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

    phantom.custom_function(custom_function="community/debug", parameters=parameters, name="debug_1")

    return


@phantom.playbook_block()
def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_3() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="and",
        conditions=[
            ["my_geo_locate_ip:action_result.data.*.country_iso_code", "!=", "US"],
            ["my_geo_locate_ip:action_result.data.*.country_iso_code", "!=", "DE"],
            ["my_geo_locate_ip:action_result.data.*.country_iso_code", "!=", "SA"],
            ["my_geo_locate_ip:action_result.data.*.country_iso_code", "!=", "CA"],
            ["my_geo_locate_ip:action_result.data.*.country_iso_code", "!=", "MX"]
        ],
        conditions_dps=[
            ["my_geo_locate_ip:action_result.data.*.country_iso_code", "!=", "US"],
            ["my_geo_locate_ip:action_result.data.*.country_iso_code", "!=", "DE"],
            ["my_geo_locate_ip:action_result.data.*.country_iso_code", "!=", "SA"],
            ["my_geo_locate_ip:action_result.data.*.country_iso_code", "!=", "CA"],
            ["my_geo_locate_ip:action_result.data.*.country_iso_code", "!=", "MX"]
        ],
        name="decision_3:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        set_sev_high(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    set_sev_low(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def set_sev_low(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("set_sev_low() called")

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
def set_sev_high(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("set_sev_high() called")

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
    phantom.debug("Chris wuz here")
    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return