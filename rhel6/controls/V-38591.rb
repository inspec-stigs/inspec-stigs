# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38591 - The rsh-server package must not be installed.'

control 'V-38591' do
  impact 1.0
  title 'The rsh-server package must not be installed.'
  desc '
The "rsh-server" package provides several obsolete and insecure network services. Removing it decreases the risk of those services\' accidental (or intentional) activation.
'
  tag 'stig','V-38591'
  tag severity: 'high'
  tag checkid: 'C-46149r1_chk'
  tag fixid: 'F-43539r1_fix'
  tag version: 'RHEL-06-000213'
  tag ruleid: 'SV-50392r1_rule'
  tag fixtext: '
The "rsh-server" package can be uninstalled with the following command:

# yum erase rsh-server
'
  tag checktext: '
Run the following command to determine if the "rsh-server" package is installed:

# rpm -q rsh-server


If the package is installed, this is a finding.
'

# START_DESCRIBE V-38591
  describe package('rsh-server') do
    it { should_not be_installed }
  end
# END_DESCRIBE V-38591

end
