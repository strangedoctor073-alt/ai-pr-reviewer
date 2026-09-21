"""AI provider abstraction.

``AIProvider`` (see :mod:`.provider`) is the contract every review engine
implements. Concrete providers live in their own modules (e.g.
:mod:`.claude`) rather than being re-exported here, so importing this
package doesn't pull in provider-specific dependencies (httpx, etc.) that a
caller who only needs the Protocol for typing doesn't need.
"""
from .provider import AIProvider

__all__ = ["AIProvider"]
