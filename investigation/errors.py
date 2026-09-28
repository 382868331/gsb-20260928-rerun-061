class InvestigationError(ValueError):
    pass


class DuplicateImportError(InvestigationError):
    def __init__(self, source_id: str):
        super().__init__(f"source already imported: {source_id}")
        self.source_id = source_id
