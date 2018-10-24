

db.clients.update({"authorizedGrantTypes": {$exists: true}}, {$rename:{"authorizedGrantTypes":"grantTypes"}}, false, true);
db.clients.update({"scopes": {$exists: true}}, {$rename:{"scopes":"scope"}}, false, true);

/* !!!! For MONGO >= 3.4 !!!! */
db.clients.aggregate([{$addFields: {clientName : "$clientId"}},{ "$out": "clients" }]);

db.clients.dropIndex("authorizedGrantTypes");
db.clients.createIndex( { "grantTypes" : 1 });
db.clients.reIndex();


