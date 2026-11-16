async def callback(request):
    code = request.query_params["code"]
    grant = await db.find_one({"code": code})
    return grant
