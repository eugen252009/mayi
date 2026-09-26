from dataclasses import dataclass
import os, pwd
@dataclass(frozen=True)
class Identity:
    uid: int
    gid: int
    name: str

def resolve_user(value: str|None) -> Identity:
    if value is None:
        uid=os.getuid(); gid=os.getgid()
        try: name=pwd.getpwuid(uid).pw_name
        except KeyError: name=str(uid)
        return Identity(uid,gid,name)
    try:
        rec=pwd.getpwnam(value)
    except KeyError:
        try: rec=pwd.getpwuid(int(value))
        except (ValueError,KeyError): raise ValueError(f"unknown user: {value}")
    return Identity(rec.pw_uid,rec.pw_gid,rec.pw_name)
