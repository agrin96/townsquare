# TODO: 1. Add a token_generation UUID to the USERS table
# 2. Add a refresh key to the Token Data.
# 3. Add a refresh endpoint to routers.user
# 4. Add token invalidation (generate new token_generation) if old refresh key is used.
# 5. Add JWTK endpoint for retrieving the public key for internal services.
# 6. Add JWTK auto rotation every X days. (keep at most 2 keys in the valid list (old + new))
# 7. Add service registration method (service_name + password (random hash in env))
# 8. Add service endpoint for registering new scopes
# 9. Add super admin method for CRUDing scopes/users/services.
