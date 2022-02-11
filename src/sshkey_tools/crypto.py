from dataclasses import dataclass
from ssl import AlertDescription

@dataclass
class Algorithm:
    pass

@dataclass
class RSA(Algorithm):
    pass

@dataclass
class DSA(Algorithm):
    pass

@dataclass
class ECDSA(Algorithm):
    pass

@dataclass
class ED25519(Algorithm):
    pass