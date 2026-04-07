from agent_redteam.adapters.callable import CallableAdapter

__all__ = ["CallableAdapter", "LLMAdapter"]


def __getattr__(name: str):
    if name == "LLMAdapter":
        from agent_redteam.adapters.llm import LLMAdapter

        return LLMAdapter
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
