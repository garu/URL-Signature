package URL::Signature::Path;

use strict;
use warnings;
use parent 'URL::Signature';
use Params::Util qw( _NONNEGINT );

our $VERSION = '0.01';


sub new {
    my ($class, %attrs) = @_;
    return $class->SUPER::new( %attrs, format => 'path' );
}

sub BUILD {
    my $self = shift;
    $self->{'as'} = 1 unless exists $self->{'as'};
    Carp::croak( q[in 'path' format, 'as' needs to be a non-negative integer])
        unless defined _NONNEGINT($self->{'as'});

    return;
}


sub extract {
    my ($self, $uri) = @_;
    my @segments = $uri->path_segments;
    return if scalar @segments <= $self->{'as'};

    my $code = splice @segments, $self->{'as'}, 1;
    $uri->path_segments( @segments );

    return ($code, $uri);
}


sub append {
    my ($self, $uri, $code) = @_;
    my @segments = $uri->path_segments;
    return if scalar @segments <= $self->{'as'};
    splice @segments, $self->{'as'}, 0, $code;
    $uri->path_segments(@segments);
    return $uri;
}


42;
__END__

=head1 NAME

URL::Signature::Path - Sign your URL's path

=head1 SYNOPSIS

  use URL::Signature::Path;
  my $signer = URL::Signature::Path->new( key => 'my-secret-key' );

  my $url = $signer->sign('/some/path');


or, from within URL::Signature:

  use URL::Signature;
  my $signer = URL::Signature->new(
    key    => 'my-secret-key',
    format => 'path',
  );


=head1 SEE ALSO

L<URL::Signature>


