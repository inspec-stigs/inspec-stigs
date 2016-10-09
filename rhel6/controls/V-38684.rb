# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38684 - The system must limit users to 10 simultaneous system logins, or a site-defined number, in accordance with operational requirements.'

control 'V-38684' do
  impact 0.1
  title 'The system must limit users to 10 simultaneous system logins, or a site-defined number, in accordance with operational requirements.'
  desc '
Limiting simultaneous user logins can insulate the system from denial of service problems caused by excessive logins. Automated login processes operating improperly or maliciously may result in an exceptional number of simultaneous login sessions.
'
  tag 'stig','V-38684'
  tag severity: 'low'
  tag checkid: 'C-46246r2_chk'
  tag fixid: 'F-43633r1_fix'
  tag version: 'RHEL-06-000319'
  tag ruleid: 'SV-50485r2_rule'
  tag fixtext: '
Limiting the number of allowed users and sessions per user can limit risks related to denial of service attacks. This addresses concurrent sessions for a single account and does not address concurrent sessions by a single user via multiple accounts. To set the number of concurrent sessions per user add the following line in "/etc/security/limits.conf":

* hard maxlogins 10

A documented site-defined number may be substituted for 10 in the above.
'
  tag checktext: '
Run the following command to ensure the "maxlogins" value is configured for all users on the system:

$ grep "maxlogins" /etc/security/limits.conf /etc/security/limits.d/*.conf

You should receive output similar to the following:

* hard maxlogins 10

If it is not similar, this is a finding.
'

# START_DESCRIBE V-38684
  tag 'limits','maxlogins'
  describe command("grep '* hard maxlogins 10' /etc/security/limits.conf /etc/security/limits.d/*.conf") do
    its('stdout') { should_not eq '' }
  end
# END_DESCRIBE V-38684

end
