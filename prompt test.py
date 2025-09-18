"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'prompt_1' block
    prompt_1(container=container)

    return

@phantom.playbook_block()
def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("prompt_1() called")

    # set approver and message variables for phantom.prompt call

    user = None
    role = "Administrator"
    message = """test"""

    # parameter list for template variable replacement
    parameters = []

    # responses
    response_types = [
        {
            "prompt": "What do you think",
            "options": {
                "type": "message",
                "required": True,
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=30, name="prompt_1", parameters=parameters, response_types=response_types, callback=debug_1)

    return


@phantom.playbook_block()
def debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_1() called")

    prompt_1_result_data = phantom.collect2(container=container, datapath=["prompt_1:action_result.status","prompt_1:action_result.parameter.message","prompt_1:action_result.summary.user","prompt_1:action_result.parameter.ttl","prompt_1:action_result.summary.answered_at","prompt_1:action_result.summary.responder_email","prompt_1:action_result.summary.sent_at","prompt_1:action_result.summary.responses.0","prompt_1:action_result.parameter.context.artifact_id"], action_results=results)

    prompt_1_result_item_0 = [item[0] for item in prompt_1_result_data]
    prompt_1_parameter_message = [item[1] for item in prompt_1_result_data]
    prompt_1_summary_user = [item[2] for item in prompt_1_result_data]
    prompt_1_parameter_ttl = [item[3] for item in prompt_1_result_data]
    prompt_1_summary_answered_at = [item[4] for item in prompt_1_result_data]
    prompt_1_summary_responder_email = [item[5] for item in prompt_1_result_data]
    prompt_1_summary_sent_at = [item[6] for item in prompt_1_result_data]
    prompt_1_summary_responses_0 = [item[7] for item in prompt_1_result_data]

    parameters = []

    parameters.append({
        "input_1": prompt_1_result_item_0,
        "input_2": prompt_1_parameter_message,
        "input_3": prompt_1_summary_user,
        "input_4": prompt_1_parameter_ttl,
        "input_5": prompt_1_summary_answered_at,
        "input_6": prompt_1_summary_responder_email,
        "input_7": prompt_1_summary_sent_at,
        "input_8": prompt_1_summary_responses_0,
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

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return