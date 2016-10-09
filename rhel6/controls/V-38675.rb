# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38675 - Process core dumps must be disabled unless needed.'

control 'V-38675' do
  impact 0.1
  title 'Process core dumps must be disabled unless needed.'
  desc '
A core dump includes a memory image taken at the time the operating system terminates an application. The memory image could contain sensitive data and is generally useful only for developers trying to debug problems.
'
  tag 'stig','V-38675'
  tag severity: 'low'
  tag checkid: 'C-46235r2_chk'
  tag fixid: 'F-43624r1_fix'
  tag version: 'RHEL-06-000308'
  tag ruleid: 'SV-50476r2_rule'
  tag fixtext: '
To disable core dumps for all users, add the following line to "/etc/security/limits.conf":

* hard core 0
'
  tag checktext: '
To verify that core dumps are disabled for all users, run the following command:

$ grep core /etc/security/limits.conf /etc/security/limits.d/*.conf

The output should be:

* hard core 0

If it is not, this is a finding.
'

# START_DESCRIBE V-38675
  tag 'limits','coredimps'
  describe command("grep '* hard core 0' /etc/security/limits.conf /etc/security/limits.d/*.conf") do
    its('content') { should_not = "" }
  end
# END_DESCRIBE V-38675

end
