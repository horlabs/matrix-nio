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
    def test_kvf_creation(self):
        alice = KVF(alice_device_id)
        assert alice.transaction_id is not None

        with pytest.raises(LocalProtocolError):
            alice.accept_verification_request()

        assert alice.done == False

    def test_kvf_request(self):
        alice = KVF(alice_device_id)
        assert alice.state == KVFState.CREATED

        request = {
            "sender": alice_id,
            "content": alice.request_verification(bob_device).content,
        }
        request_event = KeyVerificationRequest.from_dict(request)
        assert isinstance(request_event, KeyVerificationRequest)
        assert alice.state == KVFState.REQUESTED

        bob = KVF.from_key_verification_request(
            bob_device_id, alice.transaction_id, alice_device
        )
        with pytest.raises(LocalProtocolError):
            bob.request_verification(alice_device)

        assert bob.state == KVFState.REQUESTED

    def test_kvf_ready(self):
        alice = KVF(alice_device_id)
        request = {
            "sender": alice_id,
            "content": alice.request_verification(bob_device).content,
        }
        request_event = KeyVerificationRequest.from_dict(request)
        bob = KVF.from_key_verification_request(
            bob_device_id, alice.transaction_id, alice_device
        )

        ready = {"sender": bob_id, "content": bob.accept_verification_request().content}
        ready_event = KeyVerificationReady.from_dict(ready)
        assert isinstance(ready_event, KeyVerificationReady)
        assert bob.state == KVFState.READY
        alice.verification_request_accepted(bob_device)
        assert alice.state == KVFState.READY

    def test_kvf_cancellation(self):
        # TODO
        pass
