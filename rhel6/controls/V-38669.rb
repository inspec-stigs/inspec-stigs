# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38669 - The postfix service must be enabled for mail delivery.'

control 'V-38669' do
  impact 0.1
  title 'The postfix service must be enabled for mail delivery.'
  desc '
Local mail delivery is essential to some system maintenance and notification tasks.
'
  tag 'stig','V-38669'
  tag severity: 'low'
  tag checkid: 'C-46230r1_chk'
  tag fixid: 'F-43618r1_fix'
  tag version: 'RHEL-06-000287'
  tag ruleid: 'SV-50470r1_rule'
  tag fixtext: '
The Postfix mail transfer agent is used for local mail delivery within the system. The default configuration only listens for connections to the default SMTP port (port 25) on the loopback interface (127.0.0.1). It is recommended to leave this service enabled for local mail delivery. The "postfix" service can be enabled with the following command:

# chkconfig postfix on
# service postfix start
'
  tag checktext: '
Run the following command to determine the current status of the "postfix" service:

# service postfix status

If the service is enabled, it should return the following:

postfix is running...

If the service is not enabled, this is a finding.
'

# START_DESCRIBE V-38669
  tag 'postfix','service'
  describe service('postfix') do
    it { should be_enabled }
    it { should be_running }
  end
# END_DESCRIBE V-38669

end
