# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-58901 - The sudo command must require authentication.'

control 'V-58901' do
  impact 0.5
  title 'The sudo command must require authentication.'
  desc '
The "sudo" command allows authorized users to run programs (including shells) as other users, system users, and root. The "/etc/sudoers" file is used to configure authorized "sudo" users as well as the programs they are allowed to run. Some configuration options in the "/etc/sudoers" file allow configured users to run programs without re-authenticating. Use of these configuration options makes it easier for one compromised account to be used to compromise other accounts.
'
  tag 'stig','V-58901'
  tag severity: 'medium'
  tag checkid: 'C-59747r1_chk'
  tag fixid: 'F-64285r1_fix'
  tag version: 'RHEL-06-000529'
  tag ruleid: 'SV-73331r1_rule'
  tag fixtext: '
Update the "/etc/sudoers" or other sudo configuration files to remove or comment out lines utilizing the "NOPASSWD" and "!authenticate" options.

# visudo
# visudo -f [other sudo configuration file]
'
  tag checktext: '
Verify neither the "NOPASSWD" option nor the "!authenticate" option is configured for use in "/etc/sudoers" and associated files. Note that the "#include" and "#includedir" directives may be used to include configuration data from locations other than the defaults enumerated here.

# egrep \'^[^#]*NOPASSWD\' /etc/sudoers /etc/sudoers.d/*
# egrep \'^[^#]*!authenticate\' /etc/sudoers /etc/sudoers.d/*

If the "NOPASSWD" or "!authenticate" options are configured for use in "/etc/sudoers" or associated files, this is a finding.
'

# START_DESCRIBE V-58901
  # not testing this as almost all clouds use NOPASSWD for default user
# END_DESCRIBE V-58901

end
