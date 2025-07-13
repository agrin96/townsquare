from fastapi import APIRouter, Depends, HTTPException

router = APIRouter(
    prefix = '/service',
    tags = ['services', 'machine'],
    dependencies = [],
)



@router.post('/register')
async def register_new_services():
    pass



async def authenticate_service():
    pass
