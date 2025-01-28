"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'add_comment_1' block
    add_comment_1(container=container)

    return

@phantom.playbook_block()
def add_comment_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_comment_1() called")

    playbook_input_reason = phantom.collect2(container=container, datapath=["playbook_input:reason"])

    playbook_input_reason_values = [item[0] for item in playbook_input_reason]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=playbook_input_reason_values)

    pin_2(container=container)

    return


@phantom.playbook_block()
def pin_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("pin_2() called")

    playbook_input_countries = phantom.collect2(container=container, datapath=["playbook_input:countries"])

    playbook_input_countries_values = [item[0] for item in playbook_input_countries]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=playbook_input_countries_values, message="IP's not in our list of countries", pin_style="red", pin_type="card")

    format_1(container=container)

    return


@phantom.playbook_block()
def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_1() called")

    template = """Reason for exception {0}\n"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:reason"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    prompt_1(container=container)

    return


@phantom.playbook_block()
def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("prompt_1() called")

    # set user and message variables for phantom.prompt call

    user = None
    role = "Administrator"
    message = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "format_1:formatted_data"
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
            "prompt": "Please a risk score",
            "options": {
                "type": "range",
                "min": 50,
                "max": 250,
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
        "risk_score": prompt_1_summary_responses_1,
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