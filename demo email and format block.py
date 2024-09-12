"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'prompt_2' block
    prompt_2(container=container)

    return

@phantom.playbook_block()
def list_merge_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("list_merge_1() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.destinationAddress","artifact:*.cef.sourceAddress","artifact:*.id"])

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]
    container_artifact_cef_item_1 = [item[1] for item in container_artifact_data]

    parameters = []

    parameters.append({
        "input_1": container_artifact_cef_item_0,
        "input_2": container_artifact_cef_item_1,
        "input_3": None,
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

    phantom.custom_function(custom_function="community/list_merge", parameters=parameters, name="list_merge_1", callback=geolocate_ip_1)

    return


@phantom.playbook_block()
def geolocate_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("geolocate_ip_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    list_merge_1__result = phantom.collect2(container=container, datapath=["list_merge_1:custom_function_result.data.item"])

    parameters = []

    # build parameters list for 'geolocate_ip_1' call
    for list_merge_1__result_item in list_merge_1__result:
        if list_merge_1__result_item[0] is not None:
            parameters.append({
                "ip": list_merge_1__result_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("geolocate ip", parameters=parameters, name="geolocate_ip_1", assets=["maxmind"], callback=send_email_1)

    return


@phantom.playbook_block()
def send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("send_email_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    prompt_2_result_data = phantom.collect2(container=container, datapath=["prompt_2:action_result.summary.responses.0","prompt_2:action_result.parameter.context.artifact_id"], action_results=results)
    geolocate_ip_1_result_data = phantom.collect2(container=container, datapath=["geolocate_ip_1:action_result.data.*.country_name","geolocate_ip_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'send_email_1' call
    for prompt_2_result_item in prompt_2_result_data:
        for geolocate_ip_1_result_item in geolocate_ip_1_result_data:
            if prompt_2_result_item[0] is not None and geolocate_ip_1_result_item[0] is not None:
                parameters.append({
                    "from": "",
                    "to": prompt_2_result_item[0],
                    "subject": "straight from geolocate",
                    "body": geolocate_ip_1_result_item[0],
                    "context": {'artifact_id': geolocate_ip_1_result_item[1]},
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("send email", parameters=parameters, name="send_email_1", assets=["mygmail"], callback=format_1)

    return


@phantom.playbook_block()
def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_1() called")

    template = """%%\nIP: {0} is from {1}\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "geolocate_ip_1:action_result.parameter.ip",
        "geolocate_ip_1:action_result.data.*.country_name"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    send_email_formatted_data_with_dot_asterisk(container=container)

    return


@phantom.playbook_block()
def send_email_formatted_data_with_dot_asterisk(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("send_email_formatted_data_with_dot_asterisk() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    prompt_2_result_data = phantom.collect2(container=container, datapath=["prompt_2:action_result.summary.responses.0","prompt_2:action_result.parameter.context.artifact_id"], action_results=results)
    format_1__as_list = phantom.get_format_data(name="format_1__as_list")

    parameters = []

    # build parameters list for 'send_email_formatted_data_with_dot_asterisk' call
    for prompt_2_result_item in prompt_2_result_data:
        for format_1__item in format_1__as_list:
            if prompt_2_result_item[0] is not None and format_1__item is not None:
                parameters.append({
                    "to": prompt_2_result_item[0],
                    "subject": "Using formatted_data.* in the body",
                    "body": format_1__item,
                    "context": {'artifact_id': prompt_2_result_item[1]},
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("send email", parameters=parameters, name="send_email_formatted_data_with_dot_asterisk", assets=["mygmail"], callback=send_email_with_formatted_data_and_no_asterisk)

    return


@phantom.playbook_block()
def prompt_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("prompt_2() called")

    # set user and message variables for phantom.prompt call

    user = None
    role = "Administrator"
    message = """"""

    # parameter list for template variable replacement
    parameters = []

    # responses
    response_types = [
        {
            "prompt": "Please provide the email address you would like to send ",
            "options": {
                "type": "message",
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=30, name="prompt_2", parameters=parameters, response_types=response_types, callback=list_merge_1)

    return


@phantom.playbook_block()
def send_email_with_formatted_data_and_no_asterisk(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("send_email_with_formatted_data_and_no_asterisk() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    prompt_2_result_data = phantom.collect2(container=container, datapath=["prompt_2:action_result.summary.responses.0","prompt_2:action_result.parameter.context.artifact_id"], action_results=results)
    format_1 = phantom.get_format_data(name="format_1")

    parameters = []

    # build parameters list for 'send_email_with_formatted_data_and_no_asterisk' call
    for prompt_2_result_item in prompt_2_result_data:
        if prompt_2_result_item[0] is not None and format_1 is not None:
            parameters.append({
                "to": prompt_2_result_item[0],
                "subject": "Formated_data no asterisk",
                "body": format_1,
                "context": {'artifact_id': prompt_2_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("send email", parameters=parameters, name="send_email_with_formatted_data_and_no_asterisk", assets=["mygmail"])

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return