from __future__ import annotations

from enum import Enum, auto
from time import time_ns
from typing import List, Optional, Tuple
from uuid import uuid4

from ..crypto.device import OlmDevice
from ..crypto.sas import Sas
from ..event_builders import ToDeviceMessage
from ..exceptions import LocalProtocolError


class KVFState(Enum):
    CREATED = auto()
    REQUESTED = auto()
    READY = auto()
    CANCELED = auto()
    DONE = auto()


# TODO: Documentation
class KeyVerificationFramework:
    _user_cancel_error = ("m.user", "Canceled by user")
    _user_accepted_reason = (
        "m.accepted",
        "Key verification request was accepted by a different device.",
    )

    def __init__(self, own_device: str, transaction_id: Optional[str] = None):
        self.state = KVFState.CREATED
        self.own_device = own_device
        self.devices = []
        self.we_requested_it = True
        if transaction_id is None:
            self.transaction_id = str(uuid4())
        else:
            self.transaction_id = transaction_id

    @classmethod
    def from_key_verification_request(
        cls, own_device: str, transaction_id: str, requesting_device: OlmDevice
    ) -> KeyVerificationFramework:
        obj = cls(own_device, transaction_id)
        obj.we_requested_it = False
        obj.state = KVFState.REQUESTED
        obj.devices.append(requesting_device)

        return obj

    # TODO: timeout etc

    @property
    def done(self) -> bool:
        """Is the verification request canceled."""
        return self.state == KVFState.DONE

    def request_verification(self, device: OlmDevice) -> ToDeviceMessage:
        if not self.we_requested_it:
            raise LocalProtocolError(
                "Request was not started by us, can't start another request."
            )
        if self.state != KVFState.CREATED and self.state != KVFState.REQUESTED:
            raise LocalProtocolError(
                "Key verification request with the transaction id {transaction_id} already accepted."
            )

        self.state = KVFState.REQUESTED
        # TODO: Prevent same device more than once
        self.devices.append(device)

        content = {
            "from_device": self.own_device,
            "methods": [Sas._sas_method_v1],
            "transaction_id": self.transaction_id,
            "timestamp": time_ns() // 1_000_000,
        }

        message = ToDeviceMessage(
            "m.key.verification.request",
            device.user_id,
            device.id,
            content,
        )

        return message

    def accept_verification_request(self) -> ToDeviceMessage:
        """Accept a key verification request.

        Args:
            transaction_id (str): The transaction id of the interactive key
                verification.

        Returns a ``ToDeviceMessage`` that should be sent to to the homeserver.
        """
        if self.we_requested_it:
            raise LocalProtocolError(
                "Verification request was send by us, can't accept offer."
            )

        other_device = self.devices[0]

        content = {
            "from_device": self.own_device,
            "methods": [Sas._sas_method_v1],
            "transaction_id": self.transaction_id,
        }

        message = ToDeviceMessage(
            "m.key.verification.ready",
            other_device.user_id,
            other_device.id,
            content,
        )

        self.state = KVFState.READY
        return message

    def verification_request_accepted(
        self, accepting_device: OlmDevice
    ) -> List[ToDeviceMessage]:
        if accepting_device not in self.devices:
            raise LocalProtocolError(
                f"Received key verification ready from unknown device: {accepting_device.device_id}"
            )

        messages = []

        for device in self.devices:
            if accepting_device == device:
                continue

            messages.append(
                self._create_cancel_message(device, self._user_accepted_reason)
            )

        self.devices = [accepting_device]
        self.state = KVFState.READY

        return messages

    def _create_cancel_message(
        self, other_device: OlmDevice, reason: Tuple[str, str]
    ) -> ToDeviceMessage:
        cancel_code, cancel_reason = reason
        content = {
            "code": cancel_code,
            "reason": cancel_reason,
            "transaction_id": self.transaction_id,
        }

        message = ToDeviceMessage(
            "m.key.verification.cancel",
            other_device.user_id,
            other_device.id,
            content,
        )

        return message

    def cancel_verification(self, other_device: OlmDevice) -> List[ToDeviceMessage]:
        # TODO: Check state
        self.state = KVFState.CANCELED
        messages = []
        for device in self.devices:
            messages.append(
                self._create_cancel_message(device, self._user_cancel_error)
            )

        return messages

    def process_cancellation(self) -> List[ToDeviceMessage]:
        self.state = KVFState.CANCELED
        if not self.we_requested_it:
            return []

        messages = []
        for device in self.devices:
            messages.append(
                self._create_cancel_message(device, self._user_cancel_error)
            )

        return messages

    def verification_done(self) -> ToDeviceMessage:
        """Create a content dictionary to signal the end of verification."""
        if self.state == KVFState.CANCELED:
            raise LocalProtocolError("Key verification was canceled before finished")

        if self.state == KVFState.DONE:
            raise LocalProtocolError("Key verification already finished")

        if self.state != KVFState.READY:
            raise LocalProtocolError("Key verification not finished")

        message = ToDeviceMessage(
            "m.key.verification.done",
            self.devices[0].user_id,
            self.devices[0].id,
            {
                "transaction_id": self.transaction_id,
            },
        )

        self.state = KVFState.DONE

        return message
