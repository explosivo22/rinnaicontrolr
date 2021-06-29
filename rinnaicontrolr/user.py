"""Define /user endpoints."""
from typing import Awaitable, Callable

from .const import GET_USER_PAYLOAD, GET_PAYLOAD_HEADERS


class User:  # pylint: disable=too-few-public-methods
    """Define an object to handle the endpoints."""

    def __init__(self, request: Callable[..., Awaitable], user_id: str) -> None:
        """Initialize."""
        self._request: Callable[..., Awaitable] = request
        self._user_id: str = user_id

    async def get_info(
        self
    ) -> dict:
        """Return user account data.

        :rtype: ``dict``
        """
        payload = GET_USER_PAYLOAD % (self._user_id)

        user_info: dict = await self._request(
            "post",
            "https://s34ox7kri5dsvdr43bfgp6qh6i.appsync-api.us-east-1.amazonaws.com/graphql",
            data=payload,
            headers=GET_PAYLOAD_HEADERS
        )

        for items in user_info['data']['getUserByEmail']['items']:
            return items