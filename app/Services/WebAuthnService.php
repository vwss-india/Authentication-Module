<?php

namespace App\Services;

use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\Denormalizer\WebauthnSerializerFactory;

class WebAuthnService
{
    public function serializer(): SerializerInterface
    {
        return (new WebauthnSerializerFactory(AttestationStatementSupportManager::create()))->create();
    }

    public function ceremonyFactory(): CeremonyStepManagerFactory
    {
        $factory = new CeremonyStepManagerFactory;
        $factory->setSecuredRelyingPartyId([config('webauthn.rp_id')]);
        $factory->setAllowedOrigins(config('webauthn.allowed_origins', []));

        return $factory;
    }
}
