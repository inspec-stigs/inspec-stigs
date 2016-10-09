# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38546 - The IPv6 protocol handler must not be bound to the network stack unless needed.'

control 'V-38546' do
  impact 0.5
  title 'The IPv6 protocol handler must not be bound to the network stack unless needed.'
  desc '
Any unnecessary network stacks - including IPv6 - should be disabled, to reduce the vulnerability to exploitation.
'
  tag 'stig','V-38546'
  tag severity: 'medium'
  tag checkid: 'C-46104r2_chk'
  tag fixid: 'F-43494r2_fix'
  tag version: 'RHEL-06-000098'
  tag ruleid: 'SV-50347r2_rule'
  tag fixtext: '
To prevent the IPv6 kernel module ("ipv6") from binding to the IPv6 networking stack, add the following line to "/etc/modprobe.d/disabled.conf" (or another file in "/etc/modprobe.d"):

options ipv6 disable=1

This permits the IPv6 module to be loaded (and thus satisfy other modules that depend on it), while disabling support for the IPv6 protocol.
'
  tag checktext: '
If the system uses IPv6, this is not applicable.

If the system is configured to disable the "ipv6" kernel module, it will contain a line of the form:

options ipv6 disable=1

Such lines may be inside any file in "/etc/modprobe.d" or the deprecated "/etc/modprobe.conf". This permits insertion of the IPv6 kernel module (which other parts of the system expect to be present), but otherwise keeps it inactive. Run the following command to search for such lines in all files in "/etc/modprobe.d" and the deprecated "/etc/modprobe.conf":

$ grep -r ipv6 /etc/modprobe.conf /etc/modprobe.d


If the IPv6 kernel module is not disabled, this is a finding.
'

# START_DESCRIBE V-38546
  # not sure we really want this?
  # hard to test for intention...
# END_DESCRIBE V-38546

end
