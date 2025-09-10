let User= [];
let nextId=1;


class users{
    constructor(name,email){
        this.name= name;
        this.id = nextId++;
        this.email=email;
    }
};

module.exports = { User, users };