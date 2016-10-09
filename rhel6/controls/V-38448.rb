# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38448 - The /etc/gshadow file must be group-owned by root.'

control 'V-38448' do
  impact 0.5
  title 'The /etc/gshadow file must be group-owned by root.'
  desc '
The "/etc/gshadow" file contains group password hashes. Protection of this file is critical for system security.
'
  tag 'stig','V-38448'
  tag severity: 'medium'
  tag checkid: 'C-46003r1_chk'
  tag fixid: 'F-43393r1_fix'
  tag version: 'RHEL-06-000037'
  tag ruleid: 'SV-50248r1_rule'
  tag fixtext: '
To properly set the group owner of "/etc/gshadow", run the command:

# chgrp root /etc/gshadow
'
  tag checktext: '
To check the group ownership of "/etc/gshadow", run the command:

$ ls -l /etc/gshadow

If properly configured, the output should indicate the following group-owner. "root"
If it does not, this is a finding.
'

# START_DESCRIBE V-38448
  describe file('/etc/gshadow') do
    its('group') { should eq 'root' }
  end
# END_DESCRIBE V-38448

end
