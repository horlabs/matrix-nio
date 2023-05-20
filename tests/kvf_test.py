from datetime import timedelta

import pytest
from helpers import faker

from nio.crypto import KVF, KVFState, OlmDevice
from nio.events import KeyVerificationDone, KeyVerificationReady, KeyVerificationRequest
from nio.exceptions import LocalProtocolError

alice_id = "@alice:example.org"
alice_device_id = "JLAFKJWSCS"
alice_keys = faker.olm_key_pair()

bob_id = "@bob:example.org"
bob_device_id = "JLAFKJWSRS"
bob_keys = faker.olm_key_pair()

alice_device = OlmDevice(alice_id, alice_device_id, alice_keys)

bob_device = OlmDevice(bob_id, bob_device_id, bob_keys)


# TODO: SAS needed?
class TestClass:
    def test_sas_creation(self):
        alice = KVF(alice_device_id)
        assert alice.transaction_id is not None

        with pytest.raises(LocalProtocolError):
            alice.accept_verification_request()

        with pytest.raises(LocalProtocolError):
            alice.verification_request_accepted(bob_device)

        with pytest.raises(LocalProtocolError):
            alice.verification_done()

        assert alice.done == False
