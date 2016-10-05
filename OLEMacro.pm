package Mail::SpamAssassin::Plugin::OLEMacro;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Util;
use MIME::QuotedPrint;

use strict;
use warnings;
use re 'taint';

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->register_eval_rule("check_olemacro");

  return $self;
}

sub dbg {
  Mail::SpamAssassin::Plugin::dbg ("OLEMacro: @_");
}

sub check_olemacro {
  my ($self,$pms,$body,$name) = @_;

  my $conf = $pms->{main}->{conf};

  my $marker1 = "\xd0\xcf\x11\xe0";
  my $marker2 = "\x00\x41\x74\x74\x72\x69\x62\x75\x74\x00";

  foreach my $part ($pms->{msg}->find_parts(qr/./, 1)) {
    my ($ctype, $boundary, $charset, $name) =
      Mail::SpamAssassin::Util::parse_content_type($part->get_header('content-type'));

    $name = lc($name || '');

    my $cte = lc($part->get_header('content-transfer-encoding') || '');
    $ctype = lc $ctype;

    next if ($ctype =~ /text\//);

    dbg("Found attachment with name $name of type $ctype ");

    my $type = 'file';

    next unless ($cte =~ /^(?:base64|quoted\-printable)$/);

    my $data = '';

    if ($cte eq 'quoted-printable') {
      $data = decode_qp($data); # use QuotedPrint->decode_qp
    }
    else {
      $data = $part->decode();  # just use built in base64 decoder
    }

    if (index($data, $marker1) == 0 && index($data, $marker2) > -1) {
       dbg('marker found');
       return 1;
    }

  }
  return 0;
}

1;
