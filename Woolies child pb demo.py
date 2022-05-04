"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'set_severity_add_comment_promote_to_case_1' block
    set_severity_add_comment_promote_to_case_1(container=container)

    return

def set_severity_add_comment_promote_to_case_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("set_severity_add_comment_promote_to_case_1() called")

    playbook_input_commentfromanalyst = phantom.collect2(container=container, datapath=["playbook_input:commentfromanalyst"])

    playbook_input_commentfromanalyst_values = [item[0] for item in playbook_input_commentfromanalyst]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_severity(container=container, severity="high")
    phantom.comment(container=container, comment=playbook_input_commentfromanalyst_values)
    phantom.promote(container=container, template="Risk Investigation")

    container = phantom.get_container(container.get('id', None))

    send_email_1(container=container)

    return


def send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("send_email_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    playbook_input_emailaddress = phantom.collect2(container=container, datapath=["playbook_input:emailaddress"])
    playbook_input_ipandcountrylist = phantom.collect2(container=container, datapath=["playbook_input:ipandcountrylist"])
    playbook_input_commentfromanalyst = phantom.collect2(container=container, datapath=["playbook_input:commentfromanalyst"])

    parameters = []

    # build parameters list for 'send_email_1' call
    for playbook_input_emailaddress_item in playbook_input_emailaddress:
        for playbook_input_ipandcountrylist_item in playbook_input_ipandcountrylist:
            for playbook_input_commentfromanalyst_item in playbook_input_commentfromanalyst:
                if playbook_input_emailaddress_item[0] is not None and playbook_input_ipandcountrylist_item[0] is not None:
                    parameters.append({
                        "to": playbook_input_emailaddress_item[0],
                        "body": playbook_input_ipandcountrylist_item[0],
                        "subject": playbook_input_commentfromanalyst_item[0],
                    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("send email", parameters=parameters, name="send_email_1", assets=["emailserver"], callback=prompt_1)

    return


def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_1() called")

    # set user and message variables for phantom.prompt call

    user = "admin"
    message = """Comment"""

    # parameter list for template variable replacement
    parameters = []

    # responses
    response_types = [
        {
            "prompt": "Please give us your thoughts",
            "options": {
                "type": "message",
            },
        }
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_1", parameters=parameters, response_types=response_types)

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")

    prompt_1_result_data = phantom.collect2(container=container, datapath=["prompt_1:action_result.summary.responses.0"])
    send_email_1_result_data = phantom.collect2(container=container, datapath=["send_email_1:action_result.status"])

    prompt_1_summary_responses_0 = [item[0] for item in prompt_1_result_data]
    send_email_1_result_item_0 = [item[0] for item in send_email_1_result_data]

    output = {
        "responsefromchild": prompt_1_summary_responses_0,
        "emailstatus": send_email_1_result_item_0,
    }

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

    phantom.save_playbook_output_data(output=output)

    return