CREATE TABLE labels (
    src TEXT NOT NULL,
    uri TEXT NOT NULL,
    val TEXT NOT NULL,
    cts TEXT NOT NULL,
    exp TEXT,
    PRIMARY KEY (src, uri, val)
);

CREATE INDEX idx_labels_uri ON labels (uri);
CREATE INDEX idx_labels_exp ON labels (exp);
