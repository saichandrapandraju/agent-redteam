from agent_redteam.adapters.callable import CallableAdapter

__all__ = ["CallableAdapter", "LLMAdapter", "LangChainAdapter", "OpenAIAgentsAdapter"]


def __getattr__(name: str):
    if name == "LLMAdapter":
        from agent_redteam.adapters.llm import LLMAdapter

        return LLMAdapter
    if name == "LangChainAdapter":
        from agent_redteam.adapters.langchain import LangChainAdapter

        return LangChainAdapter
    if name == "OpenAIAgentsAdapter":
        from agent_redteam.adapters.openai_agents import OpenAIAgentsAdapter

        return OpenAIAgentsAdapter
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
