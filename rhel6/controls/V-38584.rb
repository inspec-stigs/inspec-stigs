# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38584 - The xinetd service must be uninstalled if no network services utilizing it are enabled.'

control 'V-38584' do
  impact 0.1
  title 'The xinetd service must be uninstalled if no network services utilizing it are enabled.'
  desc '
Removing the "xinetd" package decreases the risk of the xinetd service\'s accidental (or intentional) activation.
'
  tag 'stig','V-38584'
  tag severity: 'low'
  tag checkid: 'C-46142r1_chk'
  tag fixid: 'F-43532r1_fix'
  tag version: 'RHEL-06-000204'
  tag ruleid: 'SV-50385r1_rule'
  tag fixtext: '
The "xinetd" package can be uninstalled with the following command: 

# yum erase xinetd
'
  tag checktext: '
If network services are using the xinetd service, this is not applicable.

Run the following command to determine if the "xinetd" package is installed: 

# rpm -q xinetd


If the package is installed, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
