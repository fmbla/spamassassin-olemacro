package Mail::SpamAssassin::Plugin::OLEMacro;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Util;
use Archive::Zip qw( :ERROR_CODES :CONSTANTS );
use IO::String;

use strict;
use warnings;
use re 'taint';

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

our $VERSION = '0.1';

my $marker1 = "\xd0\xcf\x11\xe0";
my $marker2 = "\x00\x41\x74\x74\x72\x69\x62\x75\x74\x00";

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

  my $macrotypes = qr/(?:docm|dotm|potm|ppst|pptm|xlsb|xlsm|xltm)$/;
  my $exts = qr/(?:doc|dot|pot|pps|ppt|xls|xlt)$/;
  my $mimec = 0;

  foreach my $part ($pms->{msg}->find_parts(qr/./, 1)) {
    my ($ctype, $boundary, $charset, $name) =
      Mail::SpamAssassin::Util::parse_content_type($part->get_header('content-type'));

    my $cte = lc($part->get_header('content-transfer-encoding') || '');

    next unless ($cte =~ /^(?:base64)$/);

    $name = lc($name || '');
    $ctype = lc $ctype;

    dbg("Found attachment with name $name of type $ctype ");

    return 1 if $name =~ $macrotypes;

    if ($name =~ $exts) {
      my $data = $part->decode();
      if (_check_markers($data)) {
        return 1;
      }
    }

    if ($name =~ /zip$/i && $cte =~ /^base64$/){
      dbg("Found zip attachment");

      my $num_of_bytes = 512000;

      my $zip_binary_head = $part->decode($num_of_bytes);
      my $SH = IO::String->new($zip_binary_head);

      Archive::Zip::setErrorHandler( \&_zip_error_handler );
      my $zip = Archive::Zip->new();
      if($zip->readFromFileHandle( $SH ) != AZ_OK){
        dbg("cannot read zipfile $name");
        # as we cannot read it its not a zip (or too big/corrupted)
        # so skip processing.
        next;
      }

      my $filec = 0;

      my @members = $zip->members();
      foreach my $member (@members){
        my $mname = lc $member->fileName();
        return 1 if $mname =~ $macrotypes;

        $filec += 1;
        last if $filec > 5;

        if ($mname =~ $exts) {
          my ( $data, $status ) = $member->contents();
          next unless $status == AZ_OK;
          if (_check_markers($data)) {
            return 1;
          }
        }
      }

      $mimec += 1;
      last if $mimec > 5;

    }
  }
  return 0;
}

sub _check_markers {
  my ($data) = @_;
  if (index($data, $marker1) == 0 && index($data, $marker2) > -1) {
    dbg('Marker found');
    return 1;
  }
}

1;
