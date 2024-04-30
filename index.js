const modal = document.getElementById('modalEdit');
    const slotDetails = document.getElementById('slotDetails');
    slotDetails.innerText = `You are about to book the slot: ${slotId}\nRoom: ${roomName}\nStart Time: ${startTime}\nEnd Time: ${endTime}`;
    $(modal).modal('show');
    modal.dataset.slotId = slotId;
    modal.dataset.roomId = roomId;
    modal.dataset.startTime = startTime;
    modal.dataset.endTime = endTime;