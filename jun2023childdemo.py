"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'set_severity_1' block
    set_severity_1(container=container)

    return

@phantom.playbook_block()
def set_severity_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("set_severity_1() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_severity(container=container, severity="high")

    container = phantom.get_container(container.get('id', None))

    add_comment_2(container=container)

    return


@phantom.playbook_block()
def add_comment_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_comment_2() called")

    playbook_input_some_comment = phantom.collect2(container=container, datapath=["playbook_input:some_comment"])

    playbook_input_some_comment_values = [item[0] for item in playbook_input_some_comment]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=playbook_input_some_comment_values)

    pin_3(container=container)

    return


@phantom.playbook_block()
def pin_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("pin_3() called")

    playbook_input_countries = phantom.collect2(container=container, datapath=["playbook_input:countries"])
    playbook_input_ips = phantom.collect2(container=container, datapath=["playbook_input:ips"])

    playbook_input_countries_values = [item[0] for item in playbook_input_countries]
    playbook_input_ips_values = [item[0] for item in playbook_input_ips]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=playbook_input_countries_values, message=playbook_input_ips_values, pin_style="red", pin_type="card")

    prompt_1(container=container)

    return


@phantom.playbook_block()
def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_1() called")

    # set user and message variables for phantom.prompt call

    user = None
    role = "Administrator"
    message = """Hello{0}\n"""

    # parameter list for template variable replacement
    parameters = [
        ""
    ]

    # responses
    response_types = [
        {
            "prompt": "What do you think",
            "options": {
                "type": "message",
            },
        },
        {
            "prompt": "Enter in an IP",
            "options": {
                "type": "message",
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=30, name="prompt_1", parameters=parameters, response_types=response_types)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    prompt_1_result_data = phantom.collect2(container=container, datapath=["prompt_1:action_result.summary.responses.0","prompt_1:action_result.summary.responses.1"])

    prompt_1_summary_responses_0 = [item[0] for item in prompt_1_result_data]
    prompt_1_summary_responses_1 = [item[1] for item in prompt_1_result_data]

    output = {
        "thoughts": prompt_1_summary_responses_0,
        "some_ip_back": prompt_1_summary_responses_1,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_playbook_output_data(output=output)

    return