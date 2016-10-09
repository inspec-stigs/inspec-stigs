# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38689 - The Department of Defense (DoD) login banner must be displayed immediately prior to, or as part of, graphical desktop environment login prompts.'

control 'V-38689' do
  impact 0.5
  title 'The Department of Defense (DoD) login banner must be displayed immediately prior to, or as part of, graphical desktop environment login prompts.'
  desc '
An appropriate warning message reinforces policy awareness during the logon process and facilitates possible legal action against attackers.
'
  tag 'stig','V-38689'
  tag severity: 'medium'
  tag checkid: 'C-46252r3_chk'
  tag fixid: 'F-43638r2_fix'
  tag version: 'RHEL-06-000326'
  tag ruleid: 'SV-50490r3_rule'
  tag fixtext: '
To set the text shown by the GNOME Display Manager in the login screen, run the following command:

# gconftool-2
--direct \
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
--type string \
--set /apps/gdm/simple-greeter/banner_message_text \
"[DoD required text]"

Where the DoD required text is either:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests -- not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

OR:

"I\'ve read & consent to terms in IS user agreem\'t."

When entering a warning banner that spans several lines, remember to begin and end the string with """. This command writes directly to the file "/var/lib/gdm/.gconf/apps/gdm/simple-greeter/%gconf.xml", and this file can later be edited directly if necessary.
'
  tag checktext: '
If the GConf2 package is not installed, this is not applicable.

To ensure login warning banner text is properly set, run the following:

$ gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gdm/simple-greeter/banner_message_text

If properly configured, the proper banner text will appear within this schema.

The DoD required text is either:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests -- not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

OR:

"I\'ve read & consent to terms in IS user agreem\'t."

If the DoD required banner text is not appear in the schema, this is a finding.
'

# START_DESCRIBE V-38689
  tag 'gconf','GConf2','banner'
  only_if { package('GConf2').installed? }
  describe command('gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gdm/simple-greeter/banner_message_text') do
    its('stdout') { should match /read & consent/ }
  end
# END_DESCRIBE V-38689

end
