# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-51369 - The system must use a Linux Security Module configured to limit the privileges of system services.'

control 'V-51369' do
  impact 0.1
  title 'The system must use a Linux Security Module configured to limit the privileges of system services.'
  desc '
Setting the SELinux policy to "targeted" or a more specialized policy ensures the system will confine processes that are likely to be targeted for exploitation, such as network or system services.
'
  tag 'stig','V-51369'
  tag severity: 'low'
  tag checkid: 'C-53711r1_chk'
  tag fixid: 'F-56171r1_fix'
  tag version: 'RHEL-06-000023'
  tag ruleid: 'SV-65579r1_rule'
  tag fixtext: '
The SELinux "targeted" policy is appropriate for general-purpose desktops and servers, as well as systems in many other roles. To configure the system to use this policy, add or correct the following line in "/etc/selinux/config":

SELINUXTYPE=targeted

Other policies, such as "mls", provide additional security labeling and greater confinement but are not compatible with many general-purpose use cases.
'
  tag checktext: '
Check the file "/etc/selinux/config" and ensure the following line appears:

SELINUXTYPE=targeted

If it does not, this is a finding.
'

# START_DESCRIBE V-51369
  tag 'selinux','targeted','selinuxtype'
  describe parse_config_file('/etc/selinux/config') do
    its('SELINUXTYPE') { should eq 'targeted' }
  end
# END_DESCRIBE V-51369

end
