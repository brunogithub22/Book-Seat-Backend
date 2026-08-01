CREATE TABLE room (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    room_name VARCHAR(255) NOT NULL,
    flor INT NOT NULL,
    n_seat INT NOT NULL
);

CREATE TABLE seat (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    room_id UUID NOT NULL REFERENCES room(id),
    seat_description TEXT NOT NULL
);