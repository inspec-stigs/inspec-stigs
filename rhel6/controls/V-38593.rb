# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38593 - The Department of Defense (DoD) login banner must be displayed immediately prior to, or as part of, console login prompts.'

control 'V-38593' do
  impact 0.5
  title 'The Department of Defense (DoD) login banner must be displayed immediately prior to, or as part of, console login prompts.'
  desc '
An appropriate warning message reinforces policy awareness during the logon process and facilitates possible legal action against attackers.
'
  tag 'stig','V-38593'
  tag severity: 'medium'
  tag checkid: 'C-46150r1_chk'
  tag fixid: 'F-43540r1_fix'
  tag version: 'RHEL-06-000073'
  tag ruleid: 'SV-50394r1_rule'
  tag fixtext: '
To configure the system login banner:

Edit "/etc/issue". Replace the default text with a message compliant with the local site policy or a legal disclaimer. The DoD required text is either:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests -- not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

OR:

"I\'ve read & consent to terms in IS user agreem\'t."
'
  tag checktext: '
To check if the system login banner is compliant, run the following command:

$ cat /etc/issue


If it does not display the required banner, this is a finding.
'

# START_DESCRIBE V-38593
  banner_match = 'You are accessing'
  describe file('/etc/issue') do
    its('content') { should match banner_match }
  end
# END_DESCRIBE V-38593

end
