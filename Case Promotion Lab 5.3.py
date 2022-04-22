"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'compose_report' block
    compose_report(container=container)

    return

def compose_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("compose_report() called")

    template = """A file has been detected that has been determined to be potentially malicious. A case has been opened. \n\n-**Case link**: {0}\n-**Event Name**: {1}\n-**Description**: {2}\n-**Source URL**: {3}\n-**Target Server**: {4}\n-**Suspicious File Path**: {5} (*{7}*)\n-**Reason for promotion**: {6}"""

    # parameter list for template variable replacement
    parameters = [
        "container:url",
        "container:name",
        "container:description",
        "artifact:*.cef.sourceDnsDomain",
        "artifact:*.cef.destinationAddress",
        "artifact:*.cef.filePath",
        "playbook_input:promotion_reason",
        "playbook_input:hash_history"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="compose_report", drop_none=True)

    promote_to_case_add_comment_add_note_1(container=container)

    return


def promote_to_case_add_comment_add_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("promote_to_case_add_comment_add_note_1() called")

    compose_report = phantom.get_format_data(name="compose_report")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.promote(container=container, template="Data Breach")
    phantom.comment(container=container, comment="Promoted to case")
    phantom.add_note(container=container, content=compose_report, note_format="markdown", note_type="general", title="Incident Report")

    container = phantom.get_container(container.get('id', None))

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")

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

    return