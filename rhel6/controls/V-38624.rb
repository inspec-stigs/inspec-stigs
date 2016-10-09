# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38624 - System logs must be rotated daily.'

control 'V-38624' do
  impact 0.1
  title 'System logs must be rotated daily.'
  desc '
Log files that are not properly rotated run the risk of growing so large that they fill up the /var/log partition. Valuable logging information could be lost if the /var/log partition becomes full.
'
  tag 'stig','V-38624'
  tag severity: 'low'
  tag checkid: 'C-46183r1_chk'
  tag fixid: 'F-43573r1_fix'
  tag version: 'RHEL-06-000138'
  tag ruleid: 'SV-50425r1_rule'
  tag fixtext: '
The "logrotate" service should be installed or reinstalled if it is not installed and operating properly, by running the following command:

# yum reinstall logrotate
'
  tag checktext: '
Run the following commands to determine the current status of the "logrotate" service:

# grep logrotate /var/log/cron*

If the logrotate service is not run on a daily basis by cron, this is a finding.
'

# START_DESCRIBE V-38624
  tag 'logrotate','package'
  describe package('logrotate') do
    it { should be_installed }
  end
  describe command('grep logrotate /etc/cron.*/*') do
    its('stdout') { should_not eq "" }
  end
# END_DESCRIBE V-38624

end
